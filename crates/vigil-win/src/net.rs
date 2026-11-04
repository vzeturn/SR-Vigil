//! TCP connection table (`GetExtendedTcpTable`), readable without administrator rights.

use std::ffi::c_void;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use windows::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCPROW_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
};
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};

use crate::Error;

/// One TCP endpoint pair with its owning process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpConn {
    pub pid: u32,
    pub local: IpAddr,
    pub local_port: u16,
    pub remote: IpAddr,
    pub remote_port: u16,
    /// MIB state name, e.g. `established`, `listen`.
    pub state: &'static str,
}

const fn state_name(s: u32) -> &'static str {
    match s {
        1 => "closed",
        2 => "listen",
        3 => "syn_sent",
        4 => "syn_received",
        5 => "established",
        6 => "fin_wait1",
        7 => "fin_wait2",
        8 => "close_wait",
        9 => "closing",
        10 => "last_ack",
        11 => "time_wait",
        12 => "delete_tcb",
        _ => "unknown",
    }
}

/// The table stores ports in network byte order inside a `u32`.
const fn port(raw: u32) -> u16 {
    u16::from_be((raw & 0xFFFF) as u16)
}

fn fetch(family: u32) -> Result<Vec<u8>, Error> {
    let mut size = 0u32;
    for _ in 0..4 {
        let mut buf = vec![0u8; size as usize];
        // SAFETY: `buf` is writable for `size` bytes (or null/0 on the sizing call) and `size` is
        // a valid in/out pointer.
        let rc = unsafe {
            GetExtendedTcpTable(
                (size > 0).then_some(buf.as_mut_ptr().cast::<c_void>()),
                &raw mut size,
                false,
                family,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        };
        if rc == NO_ERROR.0 {
            return Ok(buf);
        }
        if rc != ERROR_INSUFFICIENT_BUFFER.0 {
            return Err(Error::Io(std::io::Error::from_raw_os_error(
                i32::try_from(rc).unwrap_or(-1),
            )));
        }
        size += 4096; // the table can grow between the sizing call and the read
    }
    Err(Error::Io(std::io::Error::other("tcp table kept growing")))
}

/// Rows of a `MIB_TCPTABLE_OWNER_PID`-shaped buffer: `u32` count, then `count` rows of `T`.
fn rows<T: Copy>(buf: &[u8]) -> Vec<T> {
    let Some(head) = buf.get(..4) else {
        return Vec::new();
    };
    let count = u32::from_le_bytes([head[0], head[1], head[2], head[3]]) as usize;
    let stride = size_of::<T>();
    (0..count)
        .filter_map(|i| {
            let start = 4 + i * stride;
            let bytes = buf.get(start..start + stride)?;
            // SAFETY: `bytes` holds exactly `size_of::<T>()` initialised bytes; `T` is a plain
            // `repr(C)` integer struct, and `read_unaligned` tolerates any alignment.
            Some(unsafe { bytes.as_ptr().cast::<T>().read_unaligned() })
        })
        .collect()
}

/// All IPv4 and IPv6 TCP endpoints on the machine.
pub fn tcp_connections() -> Result<Vec<TcpConn>, Error> {
    let mut out = Vec::new();
    let v4 = fetch(u32::from(AF_INET.0))?;
    for r in rows::<MIB_TCPROW_OWNER_PID>(&v4) {
        out.push(TcpConn {
            pid: r.dwOwningPid,
            local: IpAddr::V4(Ipv4Addr::from(u32::from_be(r.dwLocalAddr))),
            local_port: port(r.dwLocalPort),
            remote: IpAddr::V4(Ipv4Addr::from(u32::from_be(r.dwRemoteAddr))),
            remote_port: port(r.dwRemotePort),
            state: state_name(r.dwState),
        });
    }
    let v6 = fetch(u32::from(AF_INET6.0))?;
    for r in rows::<MIB_TCP6ROW_OWNER_PID>(&v6) {
        out.push(TcpConn {
            pid: r.dwOwningPid,
            local: IpAddr::V6(Ipv6Addr::from(r.ucLocalAddr)),
            local_port: port(r.dwLocalPort),
            remote: IpAddr::V6(Ipv6Addr::from(r.ucRemoteAddr)),
            remote_port: port(r.dwRemotePort),
            state: state_name(r.dwState),
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};

    #[test]
    fn sees_own_loopback_connection_with_owner_pid() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let p = l.local_addr().unwrap().port();
        let _c = TcpStream::connect(("127.0.0.1", p)).unwrap();
        let me = std::process::id();
        let all = tcp_connections().unwrap();
        assert!(
            all.iter().any(|c| c.pid == me
                && c.remote_port == p
                && c.remote == IpAddr::V4(Ipv4Addr::LOCALHOST)
                && c.state == "established"),
            "connection to port {p} not found"
        );
        assert!(
            all.iter()
                .any(|c| c.pid == me && c.local_port == p && c.state == "listen")
        );
    }
}
