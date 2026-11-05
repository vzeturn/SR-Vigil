//! Process-storm detection (`docs/04 §8`): a program that clones itself or keeps launching
//! script hosts and other living-off-the-land tools is stopped fast, in every mode.
//! Pure: the service passes the live process table, this module names the parents to stop.

use std::collections::HashMap;

/// Live children running the parent's own image at or above this count mean self-replication.
pub const REPLICATE_CHILDREN: u32 = 12;
/// A chain of this many nested same-image processes means self-replication.
pub const REPLICATE_DEPTH: u32 = 6;
/// Children (copies or script hosts) at which the advisor is asked, below every kill threshold.
pub const SUSPECT_CHILDREN: u32 = 3;
/// Seconds within which a burst of births counts as "fast".
pub const BURST_WINDOW_SECS: i64 = 10;
/// Same-image children born inside the window that already mean replication.
pub const FAST_REPLICATE: u32 = 5;
/// Script hosts born inside the window that already mean a launch flood.
pub const FAST_FLOOD: u32 = 4;
/// Live children that are script hosts and `LOLBins` at or above this count mean a launch flood.
pub const FLOOD_CHILDREN: u32 = 10;

const FLOOD_TOOLS: [&str; 12] = [
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "certutil.exe",
    "bitsadmin.exe",
    "wmic.exe",
    "msbuild.exe",
];

/// One live process.
#[derive(Debug, Clone, Copy)]
pub struct Proc<'a> {
    pub pid: u32,
    pub ppid: u32,
    pub name: &'a str,
    pub path: Option<&'a str>,
    /// Start time in unix seconds; `0` when unknown.
    pub born: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Storm {
    /// Many sibling copies of itself (browsers do this legitimately, so Safe programs are exempt).
    Replication,
    /// Copies nested generation after generation: never legitimate.
    Chain,
    /// Many dangerous helper processes.
    LaunchFlood,
}

fn same_image(a: &Proc<'_>, b: &Proc<'_>) -> bool {
    match (a.path, b.path) {
        (Some(x), Some(y)) => x.eq_ignore_ascii_case(y),
        _ => a.name.eq_ignore_ascii_case(b.name),
    }
}

fn is_flood_tool(p: &Proc<'_>) -> bool {
    FLOOD_TOOLS.iter().any(|t| p.name.eq_ignore_ascii_case(t))
}

/// Number of consecutive same-image ancestors above `p`, capped to stop on parent loops.
fn same_image_depth(p: &Proc<'_>, by_pid: &HashMap<u32, Proc<'_>>) -> usize {
    let (mut depth, mut cur) = (0, *p);
    while depth < REPLICATE_DEPTH as usize * 2 {
        match by_pid.get(&cur.ppid) {
            Some(parent) if parent.pid != cur.pid && same_image(parent, p) => {
                depth += 1;
                cur = *parent;
            }
            _ => break,
        }
    }
    depth
}

/// Births inside [`BURST_WINDOW_SECS`] of the newest one: the faster it spawns, the sooner it trips.
fn burst(born: &[i64]) -> usize {
    let newest = born.iter().copied().max().unwrap_or(0);
    if newest == 0 {
        return 0;
    }
    born.iter()
        .filter(|&&b| b > 0 && newest - b <= BURST_WINDOW_SECS)
        .count()
}

type Births = HashMap<u32, Vec<i64>>;

/// Per parent: nested-copy chains found, plus birth times of same-image and script-host children.
fn tally(procs: &[Proc<'_>]) -> (HashMap<u32, Storm>, Births, Births) {
    let by_pid: HashMap<u32, Proc<'_>> = procs.iter().map(|p| (p.pid, *p)).collect();
    let mut chains = HashMap::new();
    let (mut clones, mut tools): (Births, Births) = (HashMap::new(), HashMap::new());
    for p in procs {
        let Some(parent) = by_pid.get(&p.ppid).filter(|q| q.pid != p.pid) else {
            continue;
        };
        if same_image(p, parent) {
            clones.entry(parent.pid).or_default().push(p.born);
            if same_image_depth(p, &by_pid) >= REPLICATE_DEPTH as usize {
                chains.insert(parent.pid, Storm::Chain);
            }
        } else if is_flood_tool(p) {
            tools.entry(parent.pid).or_default().push(p.born);
        }
    }
    (chains, clones, tools)
}

/// Parents (by pid) whose live children match a storm pattern. Callers still apply the
/// never-kill guard and their own verdict policy before acting.
#[must_use]
pub fn detect(procs: &[Proc<'_>]) -> Vec<(u32, Storm)> {
    let (mut found, clones, tools) = tally(procs);
    for (pid, born) in clones {
        if born.len() >= REPLICATE_CHILDREN as usize || burst(&born) >= FAST_REPLICATE as usize {
            found.entry(pid).or_insert(Storm::Replication);
        }
    }
    for (pid, born) in tools {
        if born.len() >= FLOOD_CHILDREN as usize || burst(&born) >= FAST_FLOOD as usize {
            found.entry(pid).or_insert(Storm::LaunchFlood);
        }
    }
    let mut out: Vec<_> = found.into_iter().collect();
    out.sort_unstable_by_key(|(pid, _)| *pid);
    out
}

/// Parents with a few copies or script hosts below every kill threshold: too little to act on
/// alone, enough to put to the advisor. Returns `(pid, children)`, never a parent `detect` reports.
#[must_use]
pub fn suspects(procs: &[Proc<'_>]) -> Vec<(u32, usize)> {
    let hard: Vec<u32> = detect(procs).into_iter().map(|(p, _)| p).collect();
    let (_, clones, tools) = tally(procs);
    let mut out: Vec<(u32, usize)> = clones
        .iter()
        .chain(tools.iter())
        .filter(|(pid, b)| b.len() >= SUSPECT_CHILDREN as usize && !hard.contains(pid))
        .map(|(pid, b)| (*pid, b.len()))
        .collect();
    out.sort_unstable();
    out.dedup_by_key(|(pid, _)| *pid);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proc(id: u32, parent: u32, name: &'static str) -> Proc<'static> {
        Proc {
            pid: id,
            ppid: parent,
            name,
            path: None,
            born: 0,
        }
    }

    #[test]
    fn many_clones_are_replication() {
        let mut v = vec![proc(1, 0, "x.exe")];
        v.extend((2..2 + REPLICATE_CHILDREN).map(|i| proc(i, 1, "x.exe")));
        assert_eq!(detect(&v), vec![(1, Storm::Replication)]);
    }

    #[test]
    fn deep_chain_is_replication() {
        let v: Vec<_> = (1..=REPLICATE_DEPTH + 1)
            .map(|i| proc(i, i - 1, "x.exe"))
            .collect();
        assert!(detect(&v).iter().any(|(_, s)| *s == Storm::Chain));
    }

    #[test]
    fn many_script_hosts_are_a_flood() {
        let mut v = vec![proc(1, 0, "drop.exe")];
        v.extend((2..2 + FLOOD_CHILDREN).map(|i| proc(i, 1, "PowerShell.exe")));
        assert_eq!(detect(&v), vec![(1, Storm::LaunchFlood)]);
    }

    #[test]
    fn a_fast_burst_trips_below_the_slow_threshold() {
        let mut v = vec![proc(1, 0, "x.exe")];
        v.extend((2..2 + FAST_REPLICATE).map(|i| Proc {
            born: 1000 + i64::from(i),
            ..proc(i, 1, "x.exe")
        }));
        assert_eq!(detect(&v), vec![(1, Storm::Replication)]);
        let slow: Vec<_> = std::iter::once(proc(1, 0, "x.exe"))
            .chain((2..2 + FAST_REPLICATE).map(|i| Proc {
                born: 1000 + i64::from(i) * 60,
                ..proc(i, 1, "x.exe")
            }))
            .collect();
        assert_eq!(
            detect(&slow).len(),
            0,
            "the same count spread over minutes is fine"
        );
    }

    #[test]
    fn a_handful_is_a_suspect_not_a_storm() {
        let mut v = vec![proc(1, 0, "x.exe")];
        v.extend((2..2 + SUSPECT_CHILDREN).map(|i| proc(i, 1, "x.exe")));
        assert_eq!(detect(&v).len(), 0);
        assert_eq!(suspects(&v), vec![(1, SUSPECT_CHILDREN as usize)]);
    }

    #[test]
    fn a_few_children_are_normal() {
        let mut v = vec![proc(1, 0, "x.exe")];
        v.extend((2..6).map(|i| proc(i, 1, "x.exe")));
        v.extend((6..10).map(|i| proc(i, 1, "cmd.exe")));
        assert_eq!(detect(&v).len(), 0);
    }
}
