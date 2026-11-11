//! Real-time ETW collection (process start/stop, TCP connects and byte counts, DNS queries, file
//! activity).
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

use vigil_core::analysis::fileact;
use vigil_core::analysis::upload::UploadTracker;

use crate::Error;

const KERNEL_PROCESS: &str = "22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716";
const KERNEL_NETWORK: &str = "7dd42a49-5329-4832-8dfd-43d979153a88";
const DNS_CLIENT: &str = "1c95126e-7eea-49a9-a3fe-a378b03ddb4d";
const KERNEL_FILE: &str = "edd08927-9cc4-4e65-b970-c2560fb5c289";
/// Kernel-File keywords: CREATE (event 12, opens), `RENAME_SETLINK_PATH` (27), `CREATE_NEW_FILE` (30).
const FILE_KEYWORDS: u64 = 0x80 | 0x800 | 0x1000;
/// Events buffered for a slow consumer; beyond this new events are dropped (bounded memory).
const QUEUE: usize = 8192;

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

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
    /// NET-003: totals between `pid` and `dest` crossed the upload thresholds (once per window).
    Upload {
        pid: u32,
        dest: IpAddr,
        sent: u64,
        recv: u64,
    },
    /// A completed DNS lookup and the addresses it returned (names only, no packets).
    DnsAnswer {
        pid: u32,
        name: String,
        addrs: Vec<IpAddr>,
    },
    /// FIL-001: a new executable or script in a user-writable folder.
    FileDrop {
        pid: u32,
        path: String,
    },
    /// FIL-002 candidate: a user file renamed to a double extension; `ext` is the new final one.
    FileRenamed {
        pid: u32,
        ext: String,
    },
    /// RES-001 candidate: a credential store (index into `rules/files.toml`) was opened.
    CredentialOpen {
        pid: u32,
        store: usize,
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

/// Send/receive events are summed in `uploads` on the callback thread; only a crossed threshold
/// is queued, so per-packet volume never reaches the shared queue.
fn network_event(
    tx: &SyncSender<Event>,
    uploads: &mut UploadTracker,
    rec: &EventRecord,
    locator: &SchemaLocator,
) {
    // 10/26 = TCPv4/v6 sent, 11/27 = received, 42/43 = UDPv4 sent/received;
    // 12/28 = TCPv4/v6 connect attempt.
    let traffic = match rec.event_id() {
        10 | 26 | 42 => Some(true),
        11 | 27 | 43 => Some(false),
        12 | 28 => None,
        _ => return,
    };
    let Ok(schema) = locator.event_schema(rec) else {
        return;
    };
    let p = Parser::create(rec, &schema);
    if let Some(sent) = traffic {
        let (Ok(pid), Ok(dest), Ok(size)) = (
            p.try_parse::<u32>("PID"),
            p.try_parse::<IpAddr>("daddr"),
            p.try_parse::<u32>("size"),
        ) else {
            return;
        };
        let size = u64::from(size);
        let (s, r) = if sent { (size, 0) } else { (0, size) };
        if let Some(u) = uploads.note(pid, dest, s, r, now_ms()) {
            let _ = tx.try_send(Event::Upload {
                pid,
                dest,
                sent: u.sent,
                recv: u.recv,
            });
        }
        return;
    }
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
    // 3008 = DNS query completed, with the answers.
    if rec.event_id() != 3008 {
        return;
    }
    let Ok(schema) = locator.event_schema(rec) else {
        return;
    };
    let p = Parser::create(rec, &schema);
    let (Ok(name), Ok(results)) = (
        p.try_parse::<String>("QueryName"),
        p.try_parse::<String>("QueryResults"),
    ) else {
        return;
    };
    let addrs = parse_results(&results);
    if !addrs.is_empty() {
        let _ = tx.try_send(Event::DnsAnswer {
            pid: rec.process_id(),
            name,
            addrs,
        });
    }
}

/// Only matching file events are queued: Kernel-File is high volume and must not crowd out the
/// process and network events sharing the queue. Paths are NT device paths (`\Device\...`).
fn file_event(tx: &SyncSender<Event>, rec: &EventRecord, locator: &SchemaLocator) {
    let (id, field) = match rec.event_id() {
        12 | 30 => (rec.event_id(), "FileName"),
        // RenamePath: `FilePath` is the name after the rename.
        27 => (27, "FilePath"),
        _ => return,
    };
    let Ok(schema) = locator.event_schema(rec) else {
        return;
    };
    let Ok(path) = Parser::create(rec, &schema).try_parse::<String>(field) else {
        return;
    };
    let pid = rec.process_id();
    let ev = match id {
        12 => match fileact::sensitive_store(&path) {
            Some(store) => Event::CredentialOpen { pid, store },
            None => return,
        },
        30 if fileact::is_executable_drop(&path) => Event::FileDrop { pid, path },
        27 => match fileact::rename_extension(&path) {
            Some(ext) => Event::FileRenamed { pid, ext },
            None => return,
        },
        _ => return,
    };
    let _ = tx.try_send(ev);
}

/// `QueryResults` is `;`-separated: addresses (`1.2.3.4`, `::ffff:1.2.3.4`) mixed with
/// `type:  5 alias.example` records for CNAMEs, which are skipped.
fn parse_results(results: &str) -> Vec<IpAddr> {
    results
        .split(';')
        .filter_map(|r| r.trim().parse().ok())
        .collect()
}

/// Start a session named `name` covering Kernel-Process, Kernel-Network, DNS-Client and Kernel-File. A session
/// of that name left behind by a crashed run is stopped first (real-time sessions outlive their
/// process).
pub fn start(name: &str) -> Result<Session, Error> {
    // Absent session is the normal case; any real problem resurfaces from `start_and_process`.
    let _ = ferrisetw::trace::stop_trace_by_name(name);
    let (tx, rx) = sync_channel(QUEUE);
    let (t1, t2, t3, t4) = (tx.clone(), tx.clone(), tx.clone(), tx);
    let process = Provider::by_guid(KERNEL_PROCESS)
        .add_callback(move |r: &EventRecord, l: &SchemaLocator| process_event(&t1, r, l))
        .build();
    let mut uploads = UploadTracker::default();
    let network = Provider::by_guid(KERNEL_NETWORK)
        .add_callback(move |r: &EventRecord, l: &SchemaLocator| {
            network_event(&t2, &mut uploads, r, l);
        })
        .build();
    let dns = Provider::by_guid(DNS_CLIENT)
        .add_callback(move |r: &EventRecord, l: &SchemaLocator| dns_event(&t3, r, l))
        .build();
    let file = Provider::by_guid(KERNEL_FILE)
        .any(FILE_KEYWORDS)
        .add_callback(move |r: &EventRecord, l: &SchemaLocator| file_event(&t4, r, l))
        .build();
    let trace = UserTrace::new()
        .named(name.to_string())
        .enable(process)
        .enable(network)
        .enable(dns)
        .enable(file)
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
    fn dns_results_keep_addresses_and_skip_aliases() {
        let got = parse_results("type:  5 edge.example.net;93.184.216.34;::ffff:10.0.0.1;;");
        let want: Vec<IpAddr> = vec![
            "93.184.216.34".parse().unwrap(),
            "::ffff:10.0.0.1".parse().unwrap(),
        ];
        assert_eq!(got, want);
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
