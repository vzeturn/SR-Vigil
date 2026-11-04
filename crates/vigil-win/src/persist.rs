//! Persistence scanners and reversible actions (`docs/04 §5`).
//!
//! Registry-backed items (`run_key`, `ifeo`, `appinit`) are addressed as `HIVE\key :: value`.
//! Services are `service:<name>`, tasks `task:<path>`, startup entries are the file path.
//! Disable returns a JSON backup that [`restore`] replays exactly. Files are never deleted.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{Value, json};
use winreg::enums::{
    HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_SET_VALUE, REG_BINARY, REG_DWORD,
    REG_EXPAND_SZ, REG_MULTI_SZ, REG_QWORD, REG_SZ, RegType,
};
use winreg::{RegKey, RegValue};

/// A scanner hit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub kind: &'static str,
    pub location: String,
    pub image_path: Option<String>,
    pub command: Option<String>,
    pub risk_note: Option<String>,
}

const SEP: &str = " :: ";
const RUN_KEYS: [&str; 4] = [
    r"Software\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
];
const IFEO: &str = r"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
const WINDOWS_KEY: &str = r"Software\Microsoft\Windows NT\CurrentVersion\Windows";
const SERVICES: &str = r"SYSTEM\CurrentControlSet\Services";
const DISABLED_SUFFIX: &str = ".vigil-disabled";

fn hive(name: &str) -> Option<RegKey> {
    match name {
        "HKCU" => Some(RegKey::predef(HKEY_CURRENT_USER)),
        "HKLM" => Some(RegKey::predef(HKEY_LOCAL_MACHINE)),
        _ => None,
    }
}

fn reg_loc(h: &str, key: &str, value: &str) -> String {
    format!("{h}\\{key}{SEP}{value}")
}

fn split_reg(loc: &str) -> Result<(RegKey, String, String), String> {
    let (key, value) = loc.split_once(SEP).ok_or("malformed location")?;
    let (h, path) = key.split_once('\\').ok_or("malformed location")?;
    let root = hive(h).ok_or("unknown hive")?;
    Ok((root, path.to_string(), value.to_string()))
}

fn type_name(t: &RegType) -> &'static str {
    match t {
        REG_SZ => "sz",
        REG_EXPAND_SZ => "expand",
        REG_MULTI_SZ => "multi",
        REG_DWORD => "dword",
        REG_QWORD => "qword",
        _ => "binary",
    }
}

fn type_of(name: &str) -> RegType {
    match name {
        "sz" => REG_SZ,
        "expand" => REG_EXPAND_SZ,
        "multi" => REG_MULTI_SZ,
        "dword" => REG_DWORD,
        "qword" => REG_QWORD,
        _ => REG_BINARY,
    }
}

fn hex(b: &[u8]) -> String {
    use std::fmt::Write as _;
    b.iter().fold(String::new(), |mut s, x| {
        let _ = write!(s, "{x:02x}");
        s
    })
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

fn text_of(v: &RegValue) -> Option<String> {
    matches!(v.vtype, REG_SZ | REG_EXPAND_SZ)
        .then(|| {
            let u: Vec<u16> = v
                .bytes
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            String::from_utf16_lossy(&u)
                .trim_end_matches('\0')
                .to_string()
        })
        .filter(|s| !s.is_empty())
}

/// First token of a command line (quoted or bare), as an image path.
fn image_of(cmd: &str) -> Option<String> {
    let c = cmd.trim();
    let img = if let Some(rest) = c.strip_prefix('"') {
        rest.split('"').next()?.to_string()
    } else {
        let lower = c.to_ascii_lowercase();
        lower
            .find(".exe")
            .map_or_else(|| c.to_string(), |i| c[..i + 4].to_string())
    };
    (!img.is_empty()).then_some(img)
}

fn scan_run_keys(out: &mut Vec<Finding>) {
    for h in ["HKCU", "HKLM"] {
        let Some(root) = hive(h) else { continue };
        for key in RUN_KEYS {
            let Ok(k) = root.open_subkey_with_flags(key, KEY_READ) else {
                continue;
            };
            for (name, v) in k.enum_values().flatten() {
                let cmd = text_of(&v);
                out.push(Finding {
                    kind: "run_key",
                    location: reg_loc(h, key, &name),
                    image_path: cmd.as_deref().and_then(image_of),
                    command: cmd,
                    risk_note: None,
                });
            }
        }
    }
}

fn scan_ifeo_appinit(out: &mut Vec<Finding>) {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    if let Ok(k) = hklm.open_subkey_with_flags(IFEO, KEY_READ) {
        for sub in k.enum_keys().flatten() {
            let Ok(s) = k.open_subkey_with_flags(&sub, KEY_READ) else {
                continue;
            };
            if let Ok(v) = s.get_raw_value("Debugger") {
                let cmd = text_of(&v);
                out.push(Finding {
                    kind: "ifeo",
                    location: reg_loc("HKLM", &format!("{IFEO}\\{sub}"), "Debugger"),
                    image_path: cmd.as_deref().and_then(image_of),
                    command: cmd,
                    risk_note: Some(format!("redirects launches of {sub}")),
                });
            }
        }
    }
    if let Ok(k) = hklm.open_subkey_with_flags(WINDOWS_KEY, KEY_READ) {
        let dlls = k
            .get_raw_value("AppInit_DLLs")
            .ok()
            .and_then(|v| text_of(&v));
        if let Some(d) = dlls {
            out.push(Finding {
                kind: "appinit",
                location: reg_loc("HKLM", WINDOWS_KEY, "AppInit_DLLs"),
                image_path: image_of(&d),
                command: Some(d),
                risk_note: Some("DLLs injected into every GUI process".into()),
            });
        }
    }
}

fn scan_services(out: &mut Vec<Finding>) {
    let Ok(k) = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey_with_flags(SERVICES, KEY_READ)
    else {
        return;
    };
    for name in k.enum_keys().flatten() {
        let Ok(s) = k.open_subkey_with_flags(&name, KEY_READ) else {
            continue;
        };
        let (Ok(ty), Ok(start)) = (
            s.get_value::<u32, _>("Type"),
            s.get_value::<u32, _>("Start"),
        ) else {
            continue;
        };
        // Win32 services only (own/share process), not drivers; skip disabled ones.
        if ty & 0x30 == 0 || start == 4 {
            continue;
        }
        let cmd = s.get_raw_value("ImagePath").ok().and_then(|v| text_of(&v));
        out.push(Finding {
            kind: "service",
            location: format!("service:{name}"),
            image_path: cmd.as_deref().and_then(image_of),
            command: cmd,
            risk_note: None,
        });
    }
}

fn startup_dirs() -> Vec<PathBuf> {
    ["APPDATA", "ProgramData"]
        .iter()
        .filter_map(std::env::var_os)
        .map(|b| PathBuf::from(b).join(r"Microsoft\Windows\Start Menu\Programs\Startup"))
        .collect()
}

fn scan_startup(out: &mut Vec<Finding>) {
    for dir in startup_dirs() {
        for e in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            let p = e.path();
            let is_file = p.is_file();
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or_default();
            if !is_file || name.eq_ignore_ascii_case("desktop.ini") {
                continue;
            }
            let disabled = name.ends_with(DISABLED_SUFFIX);
            if disabled {
                continue;
            }
            let loc = p.to_string_lossy().into_owned();
            out.push(Finding {
                kind: "startup_folder",
                image_path: Some(loc.clone()),
                command: None,
                location: loc,
                risk_note: None,
            });
        }
    }
}

fn run_tool(exe: &str, args: &[&str]) -> Result<String, String> {
    let o = Command::new(exe)
        .args(args)
        .output()
        .map_err(|e| format!("{exe}: {e}"))?;
    if o.status.success() {
        Ok(String::from_utf8_lossy(&o.stdout).into_owned())
    } else {
        Err(format!("{exe} failed with {}", o.status))
    }
}

fn scan_tasks(out: &mut Vec<Finding>) {
    // `/XML ONE` emits every task as `<!-- \Name -->` followed by its definition.
    let Ok(all) = run_tool("schtasks.exe", &["/Query", "/XML", "ONE"]) else {
        return;
    };
    for chunk in all.split("<!-- ").skip(1) {
        let Some((name, xml)) = chunk.split_once(" -->") else {
            continue;
        };
        let name = name.trim();
        let Some(cmd) = tag(xml, "Command") else {
            continue;
        };
        let args = tag(xml, "Arguments").unwrap_or_default();
        out.push(Finding {
            kind: "scheduled_task",
            location: format!("task:{name}"),
            image_path: image_of(&cmd),
            command: Some(format!("{cmd} {args}").trim().to_string()),
            risk_note: None,
        });
    }
}

fn tag(xml: &str, name: &str) -> Option<String> {
    let open = format!("<{name}>");
    let s = xml.find(&open)? + open.len();
    let e = xml[s..].find(&format!("</{name}>"))? + s;
    Some(xml[s..e].trim().to_string())
}

/// Every persistence entry the scanners know about. Unreadable locations are skipped.
#[must_use]
pub fn scan() -> Vec<Finding> {
    let mut out = Vec::new();
    scan_run_keys(&mut out);
    scan_ifeo_appinit(&mut out);
    scan_services(&mut out);
    scan_startup(&mut out);
    scan_tasks(&mut out);
    out
}

fn valid_name(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= 256
        && !n.starts_with(['/', '-'])
        && n.chars()
            .all(|c| c.is_alphanumeric() || " _.-\\$".contains(c))
}

fn start_arg(code: u32) -> Option<&'static str> {
    Some(match code {
        0 => "boot",
        1 => "system",
        2 => "auto",
        3 => "demand",
        _ => return None,
    })
}

/// Disable the item and return the backup JSON that [`restore`] needs.
pub fn disable(kind: &str, location: &str) -> Result<String, String> {
    match kind {
        "run_key" | "ifeo" => {
            let (root, path, name) = split_reg(location)?;
            let k = root
                .open_subkey_with_flags(&path, KEY_READ | KEY_SET_VALUE)
                .map_err(|e| e.to_string())?;
            let v = k.get_raw_value(&name).map_err(|e| e.to_string())?;
            let backup = json!({ "type": type_name(&v.vtype), "bytes": hex(&v.bytes) });
            k.delete_value(&name).map_err(|e| e.to_string())?;
            Ok(backup.to_string())
        }
        "appinit" => {
            let (root, path, name) = split_reg(location)?;
            let k = root
                .open_subkey_with_flags(&path, KEY_READ | KEY_SET_VALUE)
                .map_err(|e| e.to_string())?;
            let v = k.get_raw_value(&name).map_err(|e| e.to_string())?;
            let backup = json!({ "type": type_name(&v.vtype), "bytes": hex(&v.bytes) });
            k.set_value(&name, &"").map_err(|e| e.to_string())?;
            Ok(backup.to_string())
        }
        "service" => {
            let name = location
                .strip_prefix("service:")
                .ok_or("malformed location")?;
            if !valid_name(name) {
                return Err("unsupported service name".into());
            }
            let k = RegKey::predef(HKEY_LOCAL_MACHINE)
                .open_subkey_with_flags(format!("{SERVICES}\\{name}"), KEY_READ)
                .map_err(|e| e.to_string())?;
            let start: u32 = k.get_value("Start").map_err(|e| e.to_string())?;
            let backup = json!({ "start": start }).to_string();
            let _ = run_tool("sc.exe", &["stop", name]);
            run_tool("sc.exe", &["config", name, "start=", "disabled"])?;
            Ok(backup)
        }
        "scheduled_task" => {
            let name = location.strip_prefix("task:").ok_or("malformed location")?;
            let xml = run_tool("schtasks.exe", &["/Query", "/TN", name, "/XML"])?;
            run_tool("schtasks.exe", &["/Change", "/TN", name, "/DISABLE"])?;
            Ok(json!({ "xml": xml }).to_string())
        }
        "startup_folder" => {
            let from = Path::new(location);
            let mut to = location.to_string();
            to.push_str(DISABLED_SUFFIX);
            std::fs::rename(from, &to).map_err(|e| e.to_string())?;
            Ok(json!({ "renamed_to": to }).to_string())
        }
        other => Err(format!("{other} items cannot be disabled")),
    }
}

/// Put the item back exactly as [`disable`] found it.
pub fn restore(kind: &str, location: &str, backup: &str) -> Result<(), String> {
    let b: Value = serde_json::from_str(backup).map_err(|e| e.to_string())?;
    match kind {
        "run_key" | "ifeo" | "appinit" => {
            let (root, path, name) = split_reg(location)?;
            let bytes = unhex(b["bytes"].as_str().ok_or("bad backup")?).ok_or("bad backup")?;
            let k = root
                .open_subkey_with_flags(&path, KEY_SET_VALUE)
                .map_err(|e| e.to_string())?;
            let vtype = type_of(b["type"].as_str().ok_or("bad backup")?);
            k.set_raw_value(&name, &RegValue { bytes, vtype })
                .map_err(|e| e.to_string())
        }
        "service" => {
            let name = location
                .strip_prefix("service:")
                .ok_or("malformed location")?;
            let code = b["start"].as_u64().and_then(|n| u32::try_from(n).ok());
            let arg = code.and_then(start_arg).ok_or("bad backup")?;
            if !valid_name(name) {
                return Err("unsupported service name".into());
            }
            run_tool("sc.exe", &["config", name, "start=", arg]).map(drop)
        }
        "scheduled_task" => {
            let name = location.strip_prefix("task:").ok_or("malformed location")?;
            run_tool("schtasks.exe", &["/Change", "/TN", name, "/ENABLE"]).map(drop)
        }
        "startup_folder" => {
            let to = b["renamed_to"].as_str().ok_or("bad backup")?;
            std::fs::rename(to, location).map_err(|e| e.to_string())
        }
        other => Err(format!("{other} items cannot be restored")),
    }
}

/// Remove the definition of an already-disabled item. Registry values are already gone after
/// Disable; services and tasks are deleted from their managers. Files are never deleted.
pub fn delete(kind: &str, location: &str) -> Result<(), String> {
    match kind {
        "run_key" | "ifeo" | "appinit" => Ok(()),
        "service" => {
            let name = location
                .strip_prefix("service:")
                .ok_or("malformed location")?;
            if !valid_name(name) {
                return Err("unsupported service name".into());
            }
            run_tool("sc.exe", &["delete", name]).map(drop)
        }
        "scheduled_task" => {
            let name = location.strip_prefix("task:").ok_or("malformed location")?;
            run_tool("schtasks.exe", &["/Delete", "/TN", name, "/F"]).map(drop)
        }
        "startup_folder" => {
            Err("Vigil never deletes files; the disabled entry stays renamed".into())
        }
        other => Err(format!("{other} items cannot be deleted")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = r"Software\VigilTest\Persist";

    #[test]
    fn run_value_disable_restore_round_trips_exactly() {
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let (k, _) = hkcu.create_subkey(KEY).unwrap();
        k.set_raw_value(
            "Updater",
            &RegValue {
                bytes: "\"C:\\Temp\\x.exe\" --silent\0"
                    .encode_utf16()
                    .flat_map(u16::to_le_bytes)
                    .collect::<Vec<u8>>(),
                vtype: REG_EXPAND_SZ,
            },
        )
        .unwrap();
        let before = k.get_raw_value("Updater").unwrap();
        let loc = reg_loc("HKCU", KEY, "Updater");

        let backup = disable("run_key", &loc).unwrap();
        assert!(k.get_raw_value("Updater").is_err(), "value must be gone");
        restore("run_key", &loc, &backup).unwrap();
        let after = k.get_raw_value("Updater").unwrap();
        assert_eq!(
            (before.vtype, &before.bytes[..]),
            (after.vtype, &after.bytes[..])
        );

        hkcu.delete_subkey_all(r"Software\VigilTest").unwrap();
    }

    #[test]
    fn scheduled_task_scan_disable_restore_round_trips() {
        let name = r"\VigilTestTask";
        let create = run_tool(
            "schtasks.exe",
            &[
                "/Create",
                "/TN",
                name,
                "/TR",
                r"C:\Windows
otepad.exe",
                "/SC",
                "ONCE",
                "/ST",
                "23:59",
                "/F",
            ],
        );
        if create.is_err() {
            return; // task creation not permitted in this environment
        }
        let loc = format!("task:{name}");
        assert!(
            scan().iter().any(|f| f.location == loc),
            "scanner finds the task"
        );
        let enabled = |want: bool| {
            let x = run_tool("schtasks.exe", &["/Query", "/TN", name, "/XML"]).unwrap();
            tag(&x, "Enabled").is_none_or(|e| e == "true") == want
        };
        assert!(enabled(true));
        let backup = disable("scheduled_task", &loc).unwrap();
        assert!(enabled(false));
        restore("scheduled_task", &loc, &backup).unwrap();
        assert!(enabled(true));
        delete("scheduled_task", &loc).unwrap();
    }

    #[test]
    fn image_of_handles_quoted_and_bare_commands() {
        assert_eq!(
            image_of(r#""C:\a b\x.exe" -q"#).as_deref(),
            Some(r"C:\a b\x.exe")
        );
        assert_eq!(image_of(r"C:\x\y.exe /s").as_deref(), Some(r"C:\x\y.exe"));
    }

    #[test]
    fn startup_entry_rename_round_trips() {
        let dir = std::env::temp_dir().join("vigil-startup-test");
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("a.lnk");
        std::fs::write(&f, b"x").unwrap();
        let loc = f.to_string_lossy().into_owned();
        let backup = disable("startup_folder", &loc).unwrap();
        assert!(!f.exists());
        restore("startup_folder", &loc, &backup).unwrap();
        assert_eq!(std::fs::read(&f).unwrap(), b"x");
        assert!(delete("startup_folder", &loc).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
