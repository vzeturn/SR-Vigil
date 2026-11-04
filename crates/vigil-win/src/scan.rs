//! One-shot static classification of the running processes. Needs no service and no elevation
//! (protected processes are skipped); shared by `vigilctl scan` and the UI's watching-only view.

use std::collections::HashMap;

use vigil_core::analysis::path::normalize;
use vigil_core::eval::Evaluation;
use vigil_core::observe::{SignerInfo, VersionInfo};
use vigil_core::rules::{RuleStore, Verdict};

use crate::observe::{env_context, evaluate_image_detailed};
use crate::process;

/// One classified process.
#[derive(Debug, Clone)]
pub struct Row {
    pub pid: u32,
    pub name: String,
    pub image: String,
    /// Process creation time (100 ns ticks since 1601); pins a PID to one process instance.
    pub start_time: Option<u64>,
    pub eval: Evaluation,
    /// Signature evidence the verdict was based on.
    pub signer: SignerInfo,
    /// Version-resource evidence (company, product, original file name).
    pub version: VersionInfo,
    pub threads: u32,
    pub ram_bytes: u64,
    /// Average CPU use over the process lifetime, in percent of one core.
    pub cpu_percent: u32,
}

/// How likely a program is to be pretending to be something it is not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Spoof {
    /// Signed and every identity clue agrees.
    Clear,
    /// Something is off (unsigned, or the signer disagrees with the file's own claims).
    Doubtful,
    /// A masquerade, impersonation or look-alike rule fired.
    Likely,
}

impl Spoof {
    /// Wire name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Clear => "clear",
            Self::Doubtful => "doubtful",
            Self::Likely => "likely",
        }
    }
}

impl Row {
    /// Impersonation assessment derived from the rules that fired plus the signature state.
    #[must_use]
    pub fn spoof(&self) -> Spoof {
        let fired = |id: &str| self.eval.signals.iter().any(|f| f.id == id);
        if ["HR-002", "HR-003", "HR-007", "SIG-015", "SIG-020"]
            .iter()
            .any(|i| fired(i))
        {
            Spoof::Likely
        } else if fired("SIG-014") || !self.signer.valid() {
            Spoof::Doubtful
        } else {
            Spoof::Clear
        }
    }
}

/// A rule that influenced a row: id, plain-language description, score delta (if a signal).
#[derive(Debug, Clone)]
pub struct Reason {
    pub id: String,
    /// Machine name of the rule, e.g. `unsigned_binary`.
    pub name: String,
    /// `signal`, `hard_rule`, `hard_allow` or `guard`.
    pub kind: &'static str,
    pub description: String,
    pub delta: Option<i32>,
}

impl Scan {
    /// The rules that fired for `row`, with their pack descriptions.
    #[must_use]
    pub fn reasons(&self, row: &Row) -> Vec<Reason> {
        row.eval
            .signals
            .iter()
            .map(|f| Reason {
                id: f.id.clone(),
                name: f.name.clone(),
                kind: kind_name(f.kind),
                description: self
                    .descriptions
                    .get(&f.id)
                    .cloned()
                    .unwrap_or_else(|| f.name.clone()),
                delta: f.delta,
            })
            .collect()
    }
}

/// Result of a scan; rows are ordered worst score first.
#[derive(Debug, Clone)]
pub struct Scan {
    pub rows: Vec<Row>,
    /// Processes whose image path could not be read (needs elevation).
    pub skipped: usize,
    pub rule_pack_version: String,
    descriptions: HashMap<String, String>,
}

impl Scan {
    #[must_use]
    pub fn count(&self, v: Verdict) -> usize {
        self.rows.iter().filter(|r| r.eval.verdict == v).count()
    }
}

/// Lifetime-average CPU use in percent of one core.
fn cpu_percent(cpu_ticks: u64, start: Option<u64>) -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    // FILETIME epoch (1601) to Unix epoch, in 100 ns ticks.
    const EPOCH_DELTA: u64 = 116_444_736_000_000_000;
    let (Some(start), Ok(now)) = (start, SystemTime::now().duration_since(UNIX_EPOCH)) else {
        return 0;
    };
    let now_ticks = EPOCH_DELTA + u64::try_from(now.as_nanos() / 100).unwrap_or(0);
    let alive = now_ticks.saturating_sub(start).max(1);
    u32::try_from(cpu_ticks.saturating_mul(100) / alive).unwrap_or(u32::MAX)
}

/// What to do about a process, judged from evidence only (never from the AI alone).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Advice {
    /// Protected or trusted: leave it alone.
    Keep,
    /// Not verified but not harmful-looking: watch it.
    Watch,
    /// Evidence says it should be ended.
    End,
}

impl Advice {
    /// Wire name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Keep => "keep",
            Self::Watch => "watch",
            Self::End => "end",
        }
    }
}

impl Row {
    /// Catalogue entry for well-known software (label and one-line purpose), if recognised.
    #[must_use]
    pub fn known(&self) -> Option<(&'static str, &'static str)> {
        vigil_core::analysis::known::lookup(
            &self.name,
            &[
                self.version.company.as_str(),
                self.version.product.as_str(),
                self.version.original_filename.as_str(),
            ],
        )
        .map(|k| (k.label.as_str(), k.what.as_str()))
    }

    /// System impact: `high` / `medium` / `low` from memory and sustained CPU.
    #[must_use]
    pub const fn impact(&self) -> &'static str {
        const MB: u64 = 1024 * 1024;
        if self.ram_bytes > 800 * MB || self.cpu_percent >= 50 {
            "high"
        } else if self.ram_bytes > 200 * MB || self.cpu_percent >= 10 {
            "medium"
        } else {
            "low"
        }
    }

    /// Recommendation: end only when the verdict is malicious or impersonation is likely and the
    /// program is not in the never-kill set; keep what is trusted or protected.
    #[must_use]
    pub fn advice(&self) -> Advice {
        if self.eval.never_kill || self.eval.verdict == Verdict::Safe {
            Advice::Keep
        } else if self.eval.verdict == Verdict::Malicious || self.spoof() == Spoof::Likely {
            Advice::End
        } else {
            Advice::Watch
        }
    }
}

/// Wire name of a rule kind.
const fn kind_name(k: vigil_core::rules::Kind) -> &'static str {
    match k {
        vigil_core::rules::Kind::Signal => "signal",
        vigil_core::rules::Kind::HardRule => "hard_rule",
        vigil_core::rules::Kind::HardAllow => "hard_allow",
        vigil_core::rules::Kind::Guard => "guard",
    }
}

/// Lower-case verdict name as used on the wire (`safe`, `unknown`, `malicious`).
#[must_use]
pub const fn verdict_name(v: Verdict) -> &'static str {
    match v {
        Verdict::Safe => "safe",
        Verdict::Unknown => "unknown",
        Verdict::Malicious => "malicious",
    }
}

/// Classify every running process once.
pub fn run() -> Result<Scan, String> {
    run_with(|_, _, _| {})
}

/// Like [`run`], but calls `on_progress(partial, done, total)` about every 100 ms while
/// classifying so a UI can show results as they become known.
pub fn run_with(mut on_progress: impl FnMut(&Scan, usize, usize)) -> Result<Scan, String> {
    let ctx = env_context().map_err(|e| format!("load rule data: {e}"))?;
    let pack = RuleStore::from_embedded()
        .map_err(|e| format!("load rule data: {e}"))?
        .active();
    let procs = process::snapshot().map_err(|e| format!("enumerate processes: {e}"))?;
    let parents = process::parent_of(&procs);

    let mut cache: HashMap<(String, Option<String>), (Evaluation, SignerInfo, VersionInfo)> =
        HashMap::new();
    let mut rows = Vec::new();
    let mut skipped = 0usize;
    let descriptions: HashMap<String, String> = pack
        .rules
        .iter()
        .map(|r| (r.id.clone(), r.description.clone()))
        .collect();
    let total = procs.len();
    let mut last = std::time::Instant::now();
    for (done, p) in procs.iter().enumerate() {
        if last.elapsed() >= std::time::Duration::from_millis(100) {
            last = std::time::Instant::now();
            let mut partial = rows.clone();
            partial.sort_by(|a: &Row, b: &Row| {
                a.eval.score.cmp(&b.eval.score).then(a.pid.cmp(&b.pid))
            });
            on_progress(
                &Scan {
                    rows: partial,
                    skipped,
                    rule_pack_version: String::new(),
                    descriptions: descriptions.clone(),
                },
                done,
                total,
            );
        }
        let Some(image) = p.image.as_deref() else {
            skipped += 1;
            continue;
        };
        let parent = parents.get(&p.pid).and_then(|pp| pp.image.clone());
        let (eval, signer, version) = cache
            .entry((normalize(image), parent.clone()))
            .or_insert_with(|| {
                evaluate_image_detailed(&ctx, &pack, image, parent.as_deref(), Some(p.pid))
            })
            .clone();
        rows.push(Row {
            pid: p.pid,
            name: p.name.clone(),
            image: image.to_owned(),
            start_time: p.start_time,
            eval,
            signer,
            version,
            threads: p.threads,
            ram_bytes: p.ram_bytes,
            cpu_percent: cpu_percent(p.cpu_ticks, p.start_time),
        });
    }
    rows.sort_by(|a, b| a.eval.score.cmp(&b.eval.score).then(a.pid.cmp(&b.pid)));
    let rule_pack_version = rows
        .first()
        .map(|r| r.eval.rule_pack_version.clone())
        .unwrap_or_default();
    Ok(Scan {
        rows,
        skipped,
        rule_pack_version,
        descriptions,
    })
}
