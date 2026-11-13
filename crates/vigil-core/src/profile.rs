//! Application profiles (`rules/app_profiles.toml`, `docs/19`): which programs are browsers whose
//! tabs may be stopped one at a time, and where a uv/pip-installed tool says it comes from.
//! Everything here is pure: command lines and file contents are untrusted input.

use std::sync::OnceLock;

use serde::Deserialize;

const EMBEDDED: &str = include_str!("../../../rules/app_profiles.toml");

/// What a browser process is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// One tab (or a group of same-site tabs): the unit that may be stopped on its own.
    Tab,
    /// The browser itself or any helper process (GPU, network, utility, crashpad).
    Other,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Browser {
    pub label: String,
    names: Vec<String>,
    engine: String,
}

#[derive(Debug, Clone, Deserialize)]
struct DevSource {
    prefix: String,
}

#[derive(Debug, Deserialize)]
struct File {
    #[serde(default)]
    browser: Vec<Browser>,
    #[serde(default)]
    dev_source: Vec<DevSource>,
}

fn file() -> &'static File {
    static F: OnceLock<File> = OnceLock::new();
    F.get_or_init(|| toml::from_str(EMBEDDED).expect("rules/app_profiles.toml is valid"))
}

/// The browser profile for an executable file name.
#[must_use]
pub fn browser(exe_name: &str) -> Option<&'static Browser> {
    file()
        .browser
        .iter()
        .find(|b| b.names.iter().any(|n| n.eq_ignore_ascii_case(exe_name)))
}

impl Browser {
    /// Role of one process of this browser, from its command line.
    #[must_use]
    pub fn role(&self, cmdline: &str) -> Role {
        let tab = match self.engine.as_str() {
            "chromium" => cmdline.split_whitespace().any(|a| a == "--type=renderer"),
            // Firefox: `firefox.exe -contentproc <flags...> <pid> tab`.
            "gecko" => {
                cmdline.contains("-contentproc")
                    && cmdline.split_whitespace().next_back() == Some("tab")
            }
            _ => false,
        };
        if tab { Role::Tab } else { Role::Other }
    }
}

/// A package installed by uv/pip into its own environment: `...\Scripts\<name>.exe` next to
/// `...\Lib\site-packages\<name>-<version>.dist-info`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DevPackage {
    /// Normalised distribution name (lower case, `-` and `_` folded to `.`).
    pub name: String,
    /// Environment root (the folder holding `Scripts` and `Lib`).
    pub env: String,
}

/// Recognise a console-script launcher by its path. `None` for anything else.
#[must_use]
pub fn dev_package(image: &str) -> Option<DevPackage> {
    let parts: Vec<&str> = image.split(['\\', '/']).collect();
    let [.., env, scripts, file] = parts.as_slice() else {
        return None;
    };
    let stem = file
        .strip_suffix(".exe")
        .or_else(|| file.strip_suffix(".EXE"))?;
    if !scripts.eq_ignore_ascii_case("scripts") || env.is_empty() || stem.is_empty() {
        return None;
    }
    let cut = image.len() - file.len() - scripts.len() - 2;
    Some(DevPackage {
        name: norm(stem),
        env: image[..cut].to_owned(),
    })
}

/// Folder (with trailing `\`) holding a program's own bundled code: the environment root for a
/// uv/pip launcher (its modules live in `Lib\site-packages`, beside `Scripts`), else its directory.
#[must_use]
pub fn install_root(image: &str) -> Option<String> {
    if let Some(p) = dev_package(image) {
        return Some(format!("{}\\", p.env));
    }
    image
        .rsplit_once(['\\', '/'])
        .map(|(dir, _)| format!("{dir}\\"))
}

fn norm(s: &str) -> String {
    s.to_lowercase().replace(['-', '_'], ".")
}

impl DevPackage {
    /// Whether a `.dist-info` folder name (`awslabs_aws_api_mcp_server-1.2.3.dist-info`) is this package's.
    #[must_use]
    pub fn owns_dist_info(&self, folder: &str) -> bool {
        folder
            .strip_suffix(".dist-info")
            .and_then(|f| f.rsplit_once('-'))
            .is_some_and(|(n, _)| norm(n) == self.name)
    }
}

/// Label prefix of the trusted source named by a package's `METADATA` (Home-page / Project-URL).
#[must_use]
pub fn trusted_source(metadata: &str) -> Option<&'static str> {
    // Only the header block (before the first blank line) is metadata; the rest is the README.
    let head = metadata.split("\n\n").next().unwrap_or("");
    head.lines().find_map(|l| {
        let (key, val) = l.split_once(':')?;
        if !matches!(key.trim(), "Home-page" | "Project-URL") {
            return None;
        }
        let url = val.find("http").map(|i| val[i..].trim().to_lowercase())?;
        file()
            .dev_source
            .iter()
            .find(|s| url.starts_with(&s.prefix))
            .map(|s| s.prefix.as_str())
    })
}

/// Share of one core above which a tab counts as runaway (`docs/19 §4`).
pub const HOT_SHARE_PERCENT: u64 = 90;
/// A tab hot this long is reported to the user.
pub const HOT_ALERT_SECS: u64 = 300;
/// A tab still hot this long is stopped in `enforce` mode.
pub const HOT_STOP_SECS: u64 = 900;

/// What a CPU sample of one tab asks the service to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HotStep {
    Quiet,
    Alert,
    Stop,
}

/// CPU history of one tab process: the last sample and since when it has been running hot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HotTab {
    ticks: u64,
    at_ms: u64,
    hot_since_ms: Option<u64>,
    alerted: bool,
}

impl HotTab {
    /// First sample: `ticks` is kernel + user time in 100 ns units.
    #[must_use]
    pub fn start(ticks: u64, at_ms: u64) -> Self {
        Self {
            ticks,
            at_ms,
            hot_since_ms: None,
            alerted: false,
        }
    }

    /// Next sample. One quiet interval resets the clock; the alert fires once per hot spell and
    /// the stop only when `enforce` is true.
    #[must_use]
    pub fn step(self, ticks: u64, at_ms: u64, enforce: bool) -> (Self, HotStep) {
        let elapsed = at_ms.saturating_sub(self.at_ms);
        if ticks < self.ticks || elapsed == 0 {
            return (Self::start(ticks, at_ms), HotStep::Quiet);
        }
        let busy_ms = (ticks - self.ticks) / 10_000;
        if busy_ms * 100 < elapsed * HOT_SHARE_PERCENT {
            return (Self::start(ticks, at_ms), HotStep::Quiet);
        }
        let since = self.hot_since_ms.unwrap_or(self.at_ms);
        let hot_secs = (at_ms - since) / 1000;
        let next = Self {
            ticks,
            at_ms,
            hot_since_ms: Some(since),
            alerted: self.alerted || hot_secs >= HOT_ALERT_SECS,
        };
        let step = if enforce && hot_secs >= HOT_STOP_SECS {
            HotStep::Stop
        } else if !self.alerted && hot_secs >= HOT_ALERT_SECS {
            HotStep::Alert
        } else {
            HotStep::Quiet
        };
        (next, step)
    }

    /// Whole minutes this tab has been running hot.
    #[must_use]
    pub fn hot_minutes(&self) -> u64 {
        self.hot_since_ms
            .map_or(0, |s| self.at_ms.saturating_sub(s) / 60_000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Samples every 10 s at `share` percent of one core, starting from `tab`.
    fn run(mut tab: HotTab, secs: u64, share: u64, enforce: bool) -> (HotTab, Vec<HotStep>) {
        let mut steps = vec![];
        for _ in 0..secs / 10 {
            let (t, s) = tab.step(
                tab.ticks + share * 10_000 * 100,
                tab.at_ms + 10_000,
                enforce,
            );
            tab = t;
            steps.push(s);
        }
        (tab, steps)
    }

    #[test]
    fn a_hot_tab_is_reported_once_at_five_minutes_and_stopped_at_fifteen_in_enforce() {
        let (tab, steps) = run(HotTab::start(0, 0), 290, 95, true);
        assert!(steps.iter().all(|s| *s == HotStep::Quiet));
        let (tab, steps) = run(tab, 600, 95, true);
        assert_eq!(steps[0], HotStep::Alert);
        assert_eq!(steps.iter().filter(|s| **s == HotStep::Alert).count(), 1);
        assert!(!steps.contains(&HotStep::Stop));
        assert_eq!(tab.hot_minutes(), 14);
        let (_, steps) = run(tab, 10, 95, true);
        assert_eq!(steps, vec![HotStep::Stop]);
    }

    #[test]
    fn observe_and_learning_only_alert_and_a_quiet_spell_resets_the_clock() {
        let (_, steps) = run(HotTab::start(0, 0), 1800, 100, false);
        assert_eq!(steps.iter().filter(|s| **s == HotStep::Alert).count(), 1);
        assert!(!steps.contains(&HotStep::Stop));
        let (tab, _) = run(HotTab::start(0, 0), 280, 100, true);
        let (tab, _) = run(tab, 10, 50, true);
        let (_, steps) = run(tab, 280, 100, true);
        assert!(steps.iter().all(|s| *s == HotStep::Quiet), "{steps:?}");
    }

    #[test]
    fn a_reused_pid_or_clock_skew_restarts_the_history() {
        let (tab, _) = run(HotTab::start(0, 0), 600, 100, true);
        assert_eq!(
            tab.step(5, tab.at_ms + 10_000, true).0,
            HotTab::start(5, tab.at_ms + 10_000)
        );
        assert_eq!(tab.step(tab.ticks, tab.at_ms, true).1, HotStep::Quiet);
    }

    #[test]
    fn chromium_tabs_are_renderers_and_nothing_else_is() {
        let edge = browser("MSEdge.exe").unwrap();
        let cmd = r#""C:\Program Files\Edge\msedge.exe" --type=renderer --lang=en-US"#;
        assert_eq!(edge.role(cmd), Role::Tab);
        for other in [
            "msedge.exe",
            "msedge.exe --type=gpu-process",
            "msedge.exe --type=utility",
        ] {
            assert_eq!(edge.role(other), Role::Other, "{other}");
        }
    }

    #[test]
    fn firefox_tabs_are_content_processes_of_type_tab() {
        let ff = browser("firefox.exe").unwrap();
        assert_eq!(
            ff.role("firefox.exe -contentproc --channel=1 3 tab"),
            Role::Tab
        );
        assert_eq!(
            ff.role("firefox.exe -contentproc --channel=1 4 gpu"),
            Role::Other
        );
        assert_eq!(ff.role("firefox.exe"), Role::Other);
    }

    #[test]
    fn only_listed_browsers_have_a_profile() {
        assert!(browser("chrome.exe").is_some());
        assert!(browser("Code.exe").is_none());
    }

    #[test]
    fn uv_launcher_is_recognised_by_its_path() {
        let p = dev_package(
            r"C:\Users\u\AppData\Local\uv\cache\archive-v0\AbC\Scripts\awslabs.aws-api-mcp-server.exe",
        )
        .unwrap();
        assert_eq!(p.name, "awslabs.aws.api.mcp.server");
        assert!(p.env.ends_with(r"archive-v0\AbC"));
        assert!(p.owns_dist_info("awslabs_aws_api_mcp_server-1.2.3.dist-info"));
        assert!(!p.owns_dist_info("awslabs_other-1.0.dist-info"));
        assert!(dev_package(r"C:\Windows\System32\cmd.exe").is_none());
        assert!(dev_package(r"C:\x\Scripts\tool.dll").is_none());
    }

    #[test]
    fn a_venv_program_owns_its_whole_environment() {
        let py = r"C:\u\uv\archive-v0\AbC\Scripts\python.exe";
        assert_eq!(
            install_root(py).as_deref(),
            Some(r"C:\u\uv\archive-v0\AbC\")
        );
        assert_eq!(
            install_root(r"C:\Apps\x\tool.exe").as_deref(),
            Some(r"C:\Apps\x\")
        );
    }

    #[test]
    fn a_source_counts_only_from_the_header_block_and_only_when_listed() {
        let ok = "Name: x\nProject-URL: Homepage, https://github.com/awslabs/mcp\n\nbody";
        assert_eq!(trusted_source(ok), Some("https://github.com/awslabs/"));
        let home = "Home-page: https://github.com/modelcontextprotocol/servers\n\n";
        assert!(trusted_source(home).is_some());
        let readme = "Name: x\n\nHome-page: https://github.com/awslabs/mcp";
        assert_eq!(trusted_source(readme), None, "README text is not metadata");
        let squat = "Home-page: https://github.com/awslabs.evil/mcp\n\n";
        assert_eq!(trusted_source(squat), None, "prefix must end at the slash");
        assert_eq!(
            trusted_source("Home-page: https://example.com/awslabs/\n\n"),
            None
        );
    }
}
