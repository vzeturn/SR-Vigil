//! Reversible switch of the IPv4 DNS servers of the connected adapters to the local filtering sinkhole
//! (`docs/23`). Uses the in-box PowerShell DNS client cmdlets with a fixed script; only numeric adapter
//! indexes and parsed IPv4 addresses are ever placed in a command, never host-provided text.

use std::net::Ipv4Addr;
use std::process::Command;

/// One connected adapter's DNS setup, as needed to put it back exactly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Adapter {
    pub index: u32,
    /// DNS comes from DHCP (no static `NameServer`), so restoring means "reset", not "set".
    pub dynamic: bool,
    pub servers: Vec<Ipv4Addr>,
}

const LIST: &str = r#"Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway } | ForEach-Object {
  $i = $_.InterfaceIndex
  $k = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\' + $_.NetAdapter.InterfaceGuid
  $ns = (Get-ItemProperty $k -ErrorAction SilentlyContinue).NameServer
  $s = (Get-DnsClientServerAddress -InterfaceIndex $i -AddressFamily IPv4).ServerAddresses -join ','
  "$i|$([int][bool]$ns)|$s"
}"#;

fn powershell(script: &str) -> Result<String, String> {
    let o = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
        .map_err(|e| format!("powershell: {e}"))?;
    if o.status.success() {
        Ok(String::from_utf8_lossy(&o.stdout).into_owned())
    } else {
        Err(format!(
            "powershell failed: {}",
            String::from_utf8_lossy(&o.stderr).trim()
        ))
    }
}

fn parse(out: &str) -> Vec<Adapter> {
    out.lines()
        .filter_map(|l| {
            let mut f = l.trim().split('|');
            let index = f.next()?.parse().ok()?;
            let is_static = f.next()? == "1";
            let servers = f
                .next()
                .unwrap_or("")
                .split(',')
                .filter_map(|s| s.trim().parse().ok())
                .collect();
            Some(Adapter {
                index,
                dynamic: !is_static,
                servers,
            })
        })
        .collect()
}

/// The adapters that currently have a default gateway.
pub fn adapters() -> Result<Vec<Adapter>, String> {
    powershell(LIST).map(|o| parse(&o))
}

/// Point one adapter at `servers` (first = preferred).
pub fn set(index: u32, servers: &[Ipv4Addr]) -> Result<(), String> {
    let list = servers
        .iter()
        .map(|s| format!("'{s}'"))
        .collect::<Vec<_>>()
        .join(",");
    powershell(&format!(
        "Set-DnsClientServerAddress -InterfaceIndex {index} -ServerAddresses ({list})"
    ))
    .map(drop)
}

/// Put one adapter back the way `a` was captured.
pub fn restore(a: &Adapter) -> Result<(), String> {
    if a.dynamic || a.servers.is_empty() {
        powershell(&format!(
            "Set-DnsClientServerAddress -InterfaceIndex {} -ResetServerAddresses",
            a.index
        ))
        .map(drop)
    } else {
        set(a.index, &a.servers)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_adapter_lines_and_skips_junk() {
        let a = parse("12|0|192.168.1.1,8.8.8.8\n7|1|\nnonsense\nx|1|1.1.1.1\n");
        assert_eq!(a.len(), 2);
        assert!(a[0].dynamic);
        assert_eq!(a[0].servers.len(), 2);
        assert!(!a[1].dynamic && a[1].servers.is_empty());
    }
}
