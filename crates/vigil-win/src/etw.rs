//! Real-time ETW collection (process start/stop, TCP connects, DNS queries).
//!
//! Needs an elevated token: `start` returns `Error::Api` with access denied otherwise, and the
//! caller degrades to snapshot-only observation.

use std::net::IpAddr;
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};

use ferrisetw::EventRecord;
use ferrisetw::parser::Parser;
use ferrisetw::provider::Provider;
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::UserTrace;

use crate::Error;

const KERNEL_PROCESS: &str = "22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716";
const KERNEL_NETWORK: &str = "7dd42a49-5329-4832-8dfd-43d979153a88";
const DNS_CLIENT: &str = "1c95126e-7eea-49a9-a3fe-a378b03ddb4d";
/// Events buffered for a slow consumer; beyond this new events are dropped (bounded memory).
const QUEUE: usize = 8192;

/// A normalised ETW event. All strings are untrusted host data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    ProcessStart {
        pid: u32,
        ppid: u32,
        image: String,
    },
    ProcessStop {
        pid: u32,
    },
    /// Outbound TCP connect attempt.
    Connect {
        pid: u32,
        dest: IpAddr,
        port: u16,
    },
    DnsQuery {
        pid: u32,
        name: String,
    },
}

/// A running trace session; dropping it stops the trace.
pub struct Session {
    _trace: UserTrace,
    events: Receiver<Event>,
}

impl Session {
    /// Events collected so far (non-blocking drain).
    #[must_use]
    pub fn drain(&self) -> Vec<Event> {
        self.events.try_iter().collect()
    }

    /// Block for the next event; `None` once the trace has stopped delivering.
    #[must_use]
    pub fn recv(&self) -> Option<Event> {
        self.events.recv().ok()
    }

    /// Wait up to `timeout` for the next event.
    #[must_use]
    pub fn recv_timeout(&self, timeout: std::time::Duration) -> Option<Event> {
        self.events.recv_timeout(timeout).ok()
    }
}

fn process_event(tx: &SyncSender<Event>, rec: &EventRecord, locator: &SchemaLocator) {
    let Ok(schema) = locator.event_schema(rec) else {
        return;
    };
    let p = Parser::create(rec, &schema);
    let ev = match rec.event_id() {
        1 => {
            let (Ok(pid), Ok(parent), Ok(image)) = (
                p.try_parse::<u32>("ProcessID"),
                p.try_parse::<u32>("ParentProcessID"),
                p.try_parse::<String>("ImageName"),
            ) else {
                return;
            };
            Event::ProcessStart {
                pid,
                ppid: parent,
                image,
            }
        }
        2 => match p.try_parse::<u32>("ProcessID") {
            Ok(pid) => Event::ProcessStop { pid },
            Err(_) => return,
        },
        _ => return,
    };
    let _ = tx.try_send(ev);
}

fn network_event(tx: &SyncSender<Event>, rec: &EventRecord, locator: &SchemaLocator) {
    // 12 = TCPv4 connect attempt, 28 = TCPv6 connect attempt.
    if !matches!(rec.event_id(), 12 | 28) {
        return;
    }
    let Ok(schema) = locator.event_schema(rec) else {
        return;
    };
    let p = Parser::create(rec, &schema);
    let (Ok(pid), Ok(dest), Ok(port)) = (
        p.try_parse::<u32>("PID"),
        p.try_parse::<IpAddr>("daddr"),
        p.try_parse::<u16>("dport"),
    ) else {
        return;
    };
    // ETW delivers `dport` in network byte order.
    let port = port.swap_bytes();
    let _ = tx.try_send(Event::Connect { pid, dest, port });
}

fn dns_event(tx: &SyncSender<Event>, rec: &EventRecord, locator: &SchemaLocator) {
    // 3006 = DNS query issued.
    if rec.event_id() != 3006 {
        return;
    }
    let Ok(schema) = locator.event_schema(rec) else {
        return;
    };
    let p = Parser::create(rec, &schema);
    if let Ok(name) = p.try_parse::<String>("QueryName") {
        let _ = tx.try_send(Event::DnsQuery {
            pid: rec.process_id(),
            name,
        });
    }
}

/// Start a session named `name` covering Kernel-Process, Kernel-Network and DNS-Client. A session
/// of that name left behind by a crashed run is stopped first (real-time sessions outlive their
/// process).
pub fn start(name: &str) -> Result<Session, Error> {
    // Absent session is the normal case; any real problem resurfaces from `start_and_process`.
    let _ = ferrisetw::trace::stop_trace_by_name(name);
    let (tx, rx) = sync_channel(QUEUE);
    let (t1, t2, t3) = (tx.clone(), tx.clone(), tx);
    let process = Provider::by_guid(KERNEL_PROCESS)
        .add_callback(move |r: &EventRecord, l: &SchemaLocator| process_event(&t1, r, l))
        .build();
    let network = Provider::by_guid(KERNEL_NETWORK)
        .add_callback(move |r: &EventRecord, l: &SchemaLocator| network_event(&t2, r, l))
        .build();
    let dns = Provider::by_guid(DNS_CLIENT)
        .add_callback(move |r: &EventRecord, l: &SchemaLocator| dns_event(&t3, r, l))
        .build();
    let trace = UserTrace::new()
        .named(name.to_string())
        .enable(process)
        .enable(network)
        .enable(dns)
        .start_and_process()
        .map_err(|e| Error::Etw(format!("{e:?}")))?;
    Ok(Session {
        _trace: trace,
        events: rx,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::time::{Duration, Instant};

    /// Collect events until `want` matches or 10 s elapse.
    fn wait_for(s: &Session, want: impl Fn(&Event) -> bool) -> Option<Event> {
        let end = Instant::now() + Duration::from_secs(10);
        while Instant::now() < end {
            if let Some(e) = s.recv_timeout(Duration::from_millis(200)) {
                if want(&e) {
                    return Some(e);
                }
            }
        }
        None
    }

    #[test]
    fn sees_process_start_and_tcp_connect() {
        let Ok(session) = start("vigil-test-etw") else {
            eprintln!("skipped: ETW needs an elevated token");
            return;
        };
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let me = std::process::id();
        let _stream = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        let connect = wait_for(
            &session,
            |e| matches!(e, Event::Connect { pid, port: p, .. } if *pid == me && *p == port),
        );
        assert!(connect.is_some(), "no Connect event for port {port}");

        let child = std::process::Command::new("whoami.exe")
            .output()
            .expect("spawn whoami");
        assert!(child.status.success());
        let start = wait_for(
            &session,
            |e| matches!(e, Event::ProcessStart { ppid, image, .. } if *ppid == me && image.to_lowercase().ends_with("whoami.exe")),
        );
        assert!(start.is_some(), "no ProcessStart for whoami.exe");
    }
}
