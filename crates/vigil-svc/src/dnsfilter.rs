//! Local DNS filter (`docs/23`): a loopback sinkhole that answers names on the enabled blocklists with
//! `0.0.0.0` / NXDOMAIN and forwards everything else to the resolver the machine used before. DNS is
//! switched to the sinkhole only while it is listening, always with the old server as fallback, and
//! restored from a backup file on disable, on stop and on the next start after a crash.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::Duration;

use serde::Deserialize;
use serde_json::{Value, json};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use vigil_core::audit::AuditKind;
use vigil_core::urlfilter::{Blocklist, Category, dns, parse_domains, parse_hosts};

use crate::state::{Shared, now};

const FEEDS_TOML: &str = include_str!("../../../rules/urlfeeds.toml");
const BACKUP: &str = "dns-backup.json";
const FEED_DIR: &str = "urlfeeds";
const MAX_FEED: usize = 32 * 1024 * 1024;
const REFRESH: Duration = Duration::from_secs(24 * 3600);
const FALLBACK_UPSTREAM: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);
const LOOPBACK: Ipv4Addr = Ipv4Addr::LOCALHOST;
const RECENT: usize = 30;

#[derive(Deserialize)]
struct Feeds {
    feed: Vec<Feed>,
}

#[derive(Deserialize, Clone)]
struct Feed {
    id: String,
    category: String,
    format: String,
    url: String,
}

#[derive(Default)]
struct Stats {
    queries: u64,
    blocked: u64,
    by_category: [u64; 4],
    recent: Vec<Value>,
    listening: bool,
    upstream: Option<SocketAddr>,
    updated: Option<String>,
}

static LIST: RwLock<Option<Blocklist>> = RwLock::new(None);
static ENABLED: Mutex<Vec<Category>> = Mutex::new(Vec::new());
static STATS: Mutex<Stats> = Mutex::new(Stats {
    queries: 0,
    blocked: 0,
    by_category: [0; 4],
    recent: Vec::new(),
    listening: false,
    upstream: None,
    updated: None,
});

fn feeds() -> Vec<Feed> {
    toml::from_str::<Feeds>(FEEDS_TOML)
        .map(|f| f.feed)
        .unwrap_or_default()
}

fn stats() -> std::sync::MutexGuard<'static, Stats> {
    STATS.lock().unwrap_or_else(PoisonError::into_inner)
}

fn wants(settings: &Value) -> (bool, Vec<Category>, Vec<String>) {
    let s = &settings["urlfilter"];
    let cats = Category::ALL
        .into_iter()
        .filter(|c| s[c.id()].as_bool() == Some(true))
        .collect();
    let allow = s["allow"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    (s["enabled"].as_bool() == Some(true), cats, allow)
}

// ---- feeds ----

fn cache_path(dir: &Path, id: &str) -> PathBuf {
    dir.join(FEED_DIR).join(format!("{id}.txt"))
}

fn build_list(dir: &Path) -> Blocklist {
    let mut list = Blocklist::default();
    for f in feeds() {
        let Some(cat) = Category::parse(&f.category) else {
            continue;
        };
        let Ok(text) = std::fs::read_to_string(cache_path(dir, &f.id)) else {
            continue;
        };
        if f.format == "hosts" {
            list.extend(parse_hosts(&text), cat);
        } else {
            list.extend(parse_domains(&text), cat);
        }
    }
    list
}

fn stale(dir: &Path, f: &Feed) -> bool {
    std::fs::metadata(cache_path(dir, &f.id))
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.elapsed().ok())
        .is_none_or(|age| age > REFRESH)
}

async fn download(client: &reqwest::Client, dir: &Path, f: &Feed) -> anyhow::Result<()> {
    anyhow::ensure!(f.url.starts_with("https://"), "feed must use https");
    let resp = client.get(&f.url).send().await?.error_for_status()?;
    anyhow::ensure!(
        resp.content_length().is_none_or(|n| n <= MAX_FEED as u64),
        "feed too large"
    );
    let body = resp.bytes().await?;
    anyhow::ensure!(
        !body.is_empty() && body.len() <= MAX_FEED,
        "feed empty or too large"
    );
    std::fs::create_dir_all(dir.join(FEED_DIR))?;
    let path = cache_path(dir, &f.id);
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, &body)?;
    std::fs::rename(&tmp, &path)?;
    Ok(())
}

async fn refresh_feeds(dir: &Path, enabled: &[Category], force: bool) -> bool {
    let Ok(client) = reqwest::Client::builder()
        .timeout(Duration::from_secs(60))
        .user_agent("vigil-dnsfilter")
        .build()
    else {
        return false;
    };
    let mut changed = false;
    for f in feeds() {
        let wanted = Category::parse(&f.category).is_some_and(|c| enabled.contains(&c));
        if !wanted || !(force || stale(dir, &f)) {
            continue;
        }
        match download(&client, dir, &f).await {
            Ok(()) => changed = true,
            Err(e) => {
                tracing::warn!(feed = %f.id, error = %e, "blocklist download failed; keeping the cached copy");
            }
        }
    }
    changed
}

fn reload(dir: &Path, allow: &[String]) {
    let mut list = build_list(dir);
    list.set_allowed(allow.iter().cloned());
    stats().updated = Some(now());
    *LIST.write().unwrap_or_else(PoisonError::into_inner) = Some(list);
}

// ---- resolution ----

fn category_slot(c: Category) -> usize {
    Category::ALL.iter().position(|x| *x == c).unwrap_or(0)
}

/// `Some(category)` when the name must be blocked right now.
fn verdict(name: &str) -> Option<Category> {
    let enabled = ENABLED
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    LIST.read()
        .unwrap_or_else(PoisonError::into_inner)
        .as_ref()?
        .check(name, &enabled)
}

/// NET-001: `name` is on a downloaded malware or phishing list, whether or not the user enabled
/// blocking for that category (an empty answer when no list has been downloaded).
#[must_use]
pub fn listed_bad(name: &str) -> bool {
    LIST.read()
        .unwrap_or_else(PoisonError::into_inner)
        .as_ref()
        .and_then(|l| l.check(name, &[Category::Malware, Category::Phishing]))
        .is_some()
}

fn record(name: &str, hit: Option<Category>) {
    let mut s = stats();
    s.queries += 1;
    if let Some(c) = hit {
        s.blocked += 1;
        s.by_category[category_slot(c)] += 1;
        s.recent
            .push(json!({ "domain": name, "category": c.id(), "at": now() }));
        if s.recent.len() > RECENT {
            s.recent.remove(0);
        }
    }
}

async fn forward_udp(pkt: &[u8], upstream: SocketAddr) -> Option<Vec<u8>> {
    let sock = UdpSocket::bind("0.0.0.0:0").await.ok()?;
    sock.connect(upstream).await.ok()?;
    sock.send(pkt).await.ok()?;
    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(Duration::from_secs(3), sock.recv(&mut buf))
        .await
        .ok()?
        .ok()?;
    buf.truncate(n);
    (buf.len() >= 2 && buf[..2] == pkt[..2]).then_some(buf)
}

async fn answer(pkt: &[u8], upstream: SocketAddr, tcp: bool) -> Option<Vec<u8>> {
    if let Some(q) = dns::parse_query(pkt) {
        let hit = verdict(&q.name);
        record(&q.name, hit);
        if hit.is_some() {
            return Some(dns::blocked_reply(pkt, &q));
        }
    }
    if tcp {
        forward_tcp(pkt, upstream).await
    } else {
        forward_udp(pkt, upstream).await
    }
}

async fn forward_tcp(pkt: &[u8], upstream: SocketAddr) -> Option<Vec<u8>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let work = async {
        let mut s = tokio::net::TcpStream::connect(upstream).await.ok()?;
        s.write_all(&u16::try_from(pkt.len()).ok()?.to_be_bytes())
            .await
            .ok()?;
        s.write_all(pkt).await.ok()?;
        let mut len = [0u8; 2];
        s.read_exact(&mut len).await.ok()?;
        let mut out = vec![0u8; usize::from(u16::from_be_bytes(len))];
        s.read_exact(&mut out).await.ok()?;
        Some(out)
    };
    tokio::time::timeout(Duration::from_secs(5), work)
        .await
        .ok()
        .flatten()
}

async fn serve_udp(sock: Arc<UdpSocket>, upstream: SocketAddr) {
    let gate = Arc::new(Semaphore::new(256));
    let mut buf = vec![0u8; 4096];
    loop {
        let Ok((n, from)) = sock.recv_from(&mut buf).await else {
            continue;
        };
        let Ok(permit) = Arc::clone(&gate).try_acquire_owned() else {
            continue; // overloaded: drop, the client retries
        };
        let (pkt, sock) = (buf[..n].to_vec(), Arc::clone(&sock));
        tokio::spawn(async move {
            if let Some(r) = answer(&pkt, upstream, false).await {
                let _ = sock.send_to(&r, from).await;
            }
            drop(permit);
        });
    }
}

async fn serve_tcp(listener: TcpListener, upstream: SocketAddr) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    loop {
        let Ok((mut conn, _)) = listener.accept().await else {
            continue;
        };
        tokio::spawn(async move {
            loop {
                let mut len = [0u8; 2];
                let read = tokio::time::timeout(Duration::from_secs(10), conn.read_exact(&mut len));
                if !matches!(read.await, Ok(Ok(_))) {
                    return;
                }
                let mut pkt = vec![0u8; usize::from(u16::from_be_bytes(len))];
                if conn.read_exact(&mut pkt).await.is_err() {
                    return;
                }
                let Some(r) = answer(&pkt, upstream, true).await else {
                    return;
                };
                let Ok(l) = u16::try_from(r.len()) else {
                    return;
                };
                if conn.write_all(&l.to_be_bytes()).await.is_err()
                    || conn.write_all(&r).await.is_err()
                {
                    return;
                }
            }
        });
    }
}

// ---- system DNS switch (Windows) ----

#[derive(Clone)]
struct Saved {
    index: u32,
    dynamic: bool,
    servers: Vec<Ipv4Addr>,
}

fn backup_json(a: &[Saved]) -> Value {
    json!(
        a.iter()
            .map(|s| json!({
                "index": s.index,
                "dynamic": s.dynamic,
                "servers": s.servers.iter().map(ToString::to_string).collect::<Vec<_>>(),
            }))
            .collect::<Vec<_>>()
    )
}

fn read_backup(dir: &Path) -> Option<Vec<Saved>> {
    let v: Value = serde_json::from_slice(&std::fs::read(dir.join(BACKUP)).ok()?).ok()?;
    v.as_array()?
        .iter()
        .map(|e| {
            Some(Saved {
                index: u32::try_from(e["index"].as_u64()?).ok()?,
                dynamic: e["dynamic"].as_bool()?,
                servers: e["servers"]
                    .as_array()?
                    .iter()
                    .filter_map(|s| s.as_str()?.parse().ok())
                    .collect(),
            })
        })
        .collect()
}

#[cfg(windows)]
mod sys {
    use super::{Ipv4Addr, LOOPBACK, Saved};

    pub fn capture() -> Result<Vec<Saved>, String> {
        Ok(vigil_win::dnsconf::adapters()?
            .into_iter()
            .map(|a| Saved {
                index: a.index,
                dynamic: a.dynamic,
                servers: a.servers,
            })
            .collect())
    }

    pub fn point_at_sinkhole(a: &Saved, upstream: Ipv4Addr) -> Result<(), String> {
        vigil_win::dnsconf::set(a.index, &[LOOPBACK, upstream])
    }

    pub fn restore(a: &Saved) -> Result<(), String> {
        vigil_win::dnsconf::restore(&vigil_win::dnsconf::Adapter {
            index: a.index,
            dynamic: a.dynamic,
            servers: a.servers.clone(),
        })
    }
}

#[cfg(not(windows))]
mod sys {
    use super::{Ipv4Addr, Saved};

    pub fn capture() -> Result<Vec<Saved>, String> {
        Err("system DNS switching needs Windows".into())
    }
    pub fn point_at_sinkhole(_: &Saved, _: Ipv4Addr) -> Result<(), String> {
        Err("needs Windows".into())
    }
    pub fn restore(_: &Saved) -> Result<(), String> {
        Err("needs Windows".into())
    }
}

/// Put DNS back from the backup file; the file is removed only when every adapter was restored.
fn restore_system(dir: &Path) {
    let Some(saved) = read_backup(dir) else {
        return;
    };
    let failed = saved
        .iter()
        .filter(|a| {
            sys::restore(a)
                .inspect_err(
                    |e| tracing::warn!(adapter = a.index, error = %e, "DNS restore failed"),
                )
                .is_err()
        })
        .count();
    if failed == 0 {
        let _ = std::fs::remove_file(dir.join(BACKUP));
    }
}

/// Capture the current setup, then point every adapter at the sinkhole with the old resolver as fallback.
fn switch_system(dir: &Path) -> Result<Ipv4Addr, String> {
    let mut current = sys::capture()?;
    // A backup left by a crash holds the real setup; the live one would already say 127.0.0.1.
    let saved = if let Some(b) = read_backup(dir) {
        b
    } else {
        current.retain(|a| !a.servers.contains(&LOOPBACK));
        std::fs::write(dir.join(BACKUP), backup_json(&current).to_string())
            .map_err(|e| format!("could not write the DNS backup: {e}"))?;
        current
    };
    let upstream = saved
        .iter()
        .flat_map(|a| a.servers.iter().copied())
        .find(|s| !s.is_loopback() && !s.is_unspecified())
        .unwrap_or(FALLBACK_UPSTREAM);
    for a in &saved {
        sys::point_at_sinkhole(a, upstream)?;
    }
    Ok(upstream)
}

// ---- service task ----

struct Live {
    tasks: Vec<JoinHandle<()>>,
}

impl Live {
    fn stop(self, dir: &Path) {
        self.tasks.iter().for_each(JoinHandle::abort);
        restore_system(dir);
        stats().listening = false;
    }
}

async fn start(dir: &Path) -> Result<Live, String> {
    let udp = UdpSocket::bind((LOOPBACK, 53))
        .await
        .map_err(|e| format!("cannot listen on 127.0.0.1:53: {e}"))?;
    let tcp = TcpListener::bind((LOOPBACK, 53))
        .await
        .map_err(|e| format!("cannot listen on 127.0.0.1:53 (tcp): {e}"))?;
    // Listening first: DNS is only redirected once something answers there.
    let upstream = SocketAddr::new(switch_system(dir)?.into(), 53);
    let mut s = stats();
    s.listening = true;
    s.upstream = Some(upstream);
    drop(s);
    Ok(Live {
        tasks: vec![
            tokio::spawn(serve_udp(Arc::new(udp), upstream)),
            tokio::spawn(serve_tcp(tcp, upstream)),
        ],
    })
}

/// Background task: follow the `urlfilter` settings, keep the lists fresh, and always leave DNS restorable.
pub async fn run(shared: Arc<Shared>, dir: PathBuf) {
    let mut live: Option<Live> = None;
    let mut last_refresh = std::time::Instant::now();
    let mut tick = tokio::time::interval(Duration::from_secs(5));
    loop {
        tick.tick().await;
        let (on, cats, allow) = wants(&shared.settings());
        let on = on && !shared.protection_paused();
        ENABLED
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone_from(&cats);
        if let Some(list) = LIST
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .as_mut()
        {
            list.set_allowed(allow.iter().cloned());
        }
        match (on, live.is_some()) {
            (true, false) => {
                refresh_feeds(&dir, &cats, false).await;
                reload(&dir, &allow);
                match start(&dir).await {
                    Ok(l) => {
                        live = Some(l);
                        shared.audit(
                            "service",
                            AuditKind::ConfigChange,
                            None,
                            &json!({"urlfilter": "on"}),
                        );
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "DNS filter not started; DNS left unchanged");
                        restore_system(&dir);
                        // Re-enable in the next settings change; avoid a retry storm.
                        let _ = shared.update_settings(&json!({"urlfilter": {"enabled": false}}));
                    }
                }
            }
            (false, true) => {
                if let Some(l) = live.take() {
                    l.stop(&dir);
                    shared.audit(
                        "service",
                        AuditKind::ConfigChange,
                        None,
                        &json!({"urlfilter": "off"}),
                    );
                }
            }
            (false, false) => restore_system(&dir), // crash recovery: a stale backup means DNS may still point here
            (true, true) => {
                if last_refresh.elapsed() > REFRESH && refresh_feeds(&dir, &cats, false).await {
                    reload(&dir, &allow);
                    last_refresh = std::time::Instant::now();
                }
            }
        }
    }
}

/// Called on service stop so DNS never stays pointed at a listener that is gone.
pub fn shutdown(dir: &Path) {
    restore_system(dir);
}

/// `dns.status`
#[must_use]
pub fn status(shared: &Shared) -> Value {
    let (on, cats, _) = wants(&shared.settings());
    let on = on && !shared.protection_paused();
    let s = stats();
    let domains = LIST
        .read()
        .unwrap_or_else(PoisonError::into_inner)
        .as_ref()
        .map_or(0, Blocklist::len);
    json!({
        "enabled": on,
        "listening": s.listening,
        "categories": cats.iter().map(|c| c.id()).collect::<Vec<_>>(),
        "domains": domains,
        "queries": s.queries,
        "blocked": s.blocked,
        "by_category": Category::ALL.iter().map(|c| (c.id().to_owned(), json!(s.by_category[category_slot(*c)]))).collect::<serde_json::Map<_, _>>(),
        "recent": s.recent,
        "upstream": s.upstream.map(|u| u.to_string()),
        "lists_loaded_at": s.updated,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_feeds_parse_and_use_https_and_known_categories() {
        let f = feeds();
        assert!(f.len() >= 4);
        for x in f {
            assert!(x.url.starts_with("https://"), "{}", x.id);
            assert!(Category::parse(&x.category).is_some(), "{}", x.id);
            assert!(matches!(x.format.as_str(), "hosts" | "domains"), "{}", x.id);
        }
    }

    #[test]
    fn backup_round_trips() {
        let s = vec![Saved {
            index: 9,
            dynamic: false,
            servers: vec![Ipv4Addr::new(9, 9, 9, 9)],
        }];
        let dir = std::env::temp_dir().join(format!("vigil-dns-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(BACKUP), backup_json(&s).to_string()).unwrap();
        let back = read_backup(&dir).unwrap();
        assert_eq!((back[0].index, back[0].dynamic), (9, false));
        assert_eq!(back[0].servers, s[0].servers);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn blocked_names_are_answered_locally_and_counted() {
        let mut list = Blocklist::default();
        list.extend(["evil.example".to_string()], Category::Malware);
        *LIST.write().unwrap() = Some(list);
        *ENABLED.lock().unwrap() = vec![Category::Malware];
        let mut q = vec![0xab, 0xcd, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        for l in ["evil", "example"] {
            q.push(u8::try_from(l.len()).unwrap());
            q.extend_from_slice(l.as_bytes());
        }
        q.extend_from_slice(&[0, 0, 1, 0, 1]);
        let r = answer(&q, "127.0.0.1:9".parse().unwrap(), false)
            .await
            .unwrap();
        assert_eq!(&r[..2], &[0xab, 0xcd]);
        assert_eq!(r[7], 1, "one answer");
        assert!(stats().blocked >= 1);
    }
}
