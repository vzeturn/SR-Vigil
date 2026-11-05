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

#[cfg(test)]
mod tests {
    use super::*;

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
