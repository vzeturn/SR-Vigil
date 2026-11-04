//! Kill policy (`docs/04 §3`): the never-kill guard SG-001 and tree ordering. Pure and OS-free.

use std::collections::{HashMap, HashSet};

use crate::analysis::path::basename;

/// Hard rules that lift SG-001: the process is provably impersonating a system binary.
const LIFTING_RULES: [&str; 3] = ["HR-001", "HR-002", "HR-003"];

/// Why a kill was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// Member of the never-kill set (or a pseudo-process) with no lifting hard rule.
    NeverKill,
    /// The process is Vigil itself or one of its components.
    SelfProcess,
}

/// Names that must never be killed: `never_kill = true` entries plus pseudo-processes.
#[derive(Debug, Clone, Default)]
pub struct NeverKill {
    names: HashSet<String>,
}

impl NeverKill {
    #[must_use]
    pub fn new(names: impl IntoIterator<Item = String>) -> Self {
        Self {
            names: names.into_iter().map(|n| n.to_ascii_lowercase()).collect(),
        }
    }

    /// SG-001. `image` is a path or a bare name; `hard_rule` is the identity's fired hard rule.
    ///
    /// # Errors
    /// [`Refusal::NeverKill`] when the name is protected and no lifting hard rule fired.
    pub fn check(&self, image: &str, hard_rule: Option<&str>) -> Result<(), Refusal> {
        let name = basename(image).to_ascii_lowercase();
        let lifted = hard_rule.is_some_and(|r| LIFTING_RULES.contains(&r));
        if self.names.contains(&name) && !lifted {
            Err(Refusal::NeverKill)
        } else {
            Ok(())
        }
    }
}

/// A process as the tree walker sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    pub pid: u32,
    pub ppid: u32,
    /// Sortable creation time; a child must be newer than its parent to count as a descendant.
    pub started: u64,
}

/// `root` plus all live descendants, leaves first (so a parent cannot respawn a killed child).
/// PID reuse is handled by requiring `child.started >= parent.started`.
#[must_use]
pub fn tree_order(root: u32, procs: &[Node]) -> Vec<u32> {
    let by_pid: HashMap<u32, &Node> = procs.iter().map(|n| (n.pid, n)).collect();
    let Some(start) = by_pid.get(&root) else {
        return Vec::new();
    };
    let mut children: HashMap<u32, Vec<&Node>> = HashMap::new();
    for n in procs {
        if n.pid != n.ppid {
            children.entry(n.ppid).or_default().push(n);
        }
    }
    let mut out = Vec::new();
    let mut seen = HashSet::from([root]);
    walk(start, &children, &mut seen, &mut out);
    out
}

fn walk(
    node: &Node,
    children: &HashMap<u32, Vec<&Node>>,
    seen: &mut HashSet<u32>,
    out: &mut Vec<u32>,
) {
    for c in children.get(&node.pid).into_iter().flatten() {
        if c.started >= node.started && seen.insert(c.pid) {
            walk(c, children, seen, out);
        }
    }
    out.push(node.pid);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn guard() -> NeverKill {
        NeverKill::new(["lsass.exe".into(), "System".into()])
    }

    #[test]
    fn never_kill_names_are_refused_case_insensitively() {
        assert_eq!(
            guard().check(r"C:\Windows\System32\LSASS.EXE", None),
            Err(Refusal::NeverKill)
        );
        assert_eq!(guard().check("system", None), Err(Refusal::NeverKill));
        assert_eq!(guard().check(r"C:\x\evil.exe", None), Ok(()));
    }

    #[test]
    fn only_impersonation_rules_lift_the_guard() {
        for r in ["HR-001", "HR-002", "HR-003"] {
            assert_eq!(guard().check(r"C:\Temp\lsass.exe", Some(r)), Ok(()));
        }
        assert_eq!(
            guard().check(r"C:\Temp\lsass.exe", Some("HR-004")),
            Err(Refusal::NeverKill)
        );
    }

    fn n(pid: u32, parent: u32, started: u64) -> Node {
        Node {
            pid,
            ppid: parent,
            started,
        }
    }

    #[test]
    fn tree_is_leaves_first_and_root_last() {
        let procs = [n(1, 0, 1), n(2, 1, 2), n(3, 2, 3), n(4, 1, 4), n(9, 8, 9)];
        let order = tree_order(2, &procs);
        assert_eq!(order, vec![3, 2]);
        let all = tree_order(1, &procs);
        assert_eq!(all.last(), Some(&1));
        assert!(all.iter().position(|p| *p == 3) < all.iter().position(|p| *p == 2));
        assert!(!all.contains(&9));
    }

    #[test]
    fn reused_parent_pid_does_not_adopt_older_processes() {
        // pid 5 was reused: the "child" 6 started before the new pid 5 existed.
        let procs = [n(5, 1, 100), n(6, 5, 50)];
        assert_eq!(tree_order(5, &procs), vec![5]);
    }

    #[test]
    fn cycles_terminate() {
        let procs = [n(1, 2, 1), n(2, 1, 2)];
        assert_eq!(tree_order(1, &procs).len(), 2);
    }

    #[test]
    fn unknown_root_yields_nothing() {
        assert_eq!(tree_order(7, &[n(1, 0, 1)]), Vec::<u32>::new());
    }
}
