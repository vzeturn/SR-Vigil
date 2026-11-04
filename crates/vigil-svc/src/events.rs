//! Server-pushed events: per-connection topic filter plus batching (`docs/05 §5`).

use std::collections::HashSet;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::sync::broadcast::{self, error::RecvError};
use tokio::sync::mpsc::UnboundedSender;
use vigil_ipc::proto::Notification;

/// Topics a client may subscribe to.
pub const TOPICS: [&str; 7] = [
    "processes",
    "connections",
    "verdicts",
    "pending",
    "enforcement",
    "alerts",
    "health",
];

/// Maximum events per `event.batch` and the flush interval.
pub const BATCH_MAX: usize = 200;
pub const BATCH_EVERY: Duration = Duration::from_millis(100);

/// One event on the service-wide bus.
#[derive(Debug, Clone)]
pub struct Event {
    pub topic: &'static str,
    pub method: &'static str,
    pub params: Value,
}

/// Topics whose events are batched.
const fn batched(topic: &str) -> bool {
    matches!(topic.as_bytes(), b"processes" | b"connections")
}

fn notification(method: &str, params: Value) -> Notification {
    Notification {
        jsonrpc: "2.0".into(),
        method: method.into(),
        params: Some(params),
    }
}

fn flush(buf: &mut Vec<Value>, out: &UnboundedSender<Notification>) -> bool {
    if buf.is_empty() {
        return true;
    }
    let events = std::mem::take(buf);
    out.send(notification("event.batch", json!({ "events": events })))
        .is_ok()
}

/// Forward bus events for the subscribed topics to one connection until it goes away.
pub async fn forward(
    mut bus: broadcast::Receiver<Event>,
    topics: Arc<Mutex<HashSet<String>>>,
    out: UnboundedSender<Notification>,
) {
    let mut tick = tokio::time::interval(BATCH_EVERY);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    tick.tick().await; // the first tick is immediate; consume it so batches fill to the size cap
    let mut buf: Vec<Value> = Vec::new();
    loop {
        tokio::select! {
            ev = bus.recv() => match ev {
                Ok(e) => {
                    let wanted = topics.lock().unwrap_or_else(PoisonError::into_inner).contains(e.topic);
                    if !wanted { continue; }
                    if batched(e.topic) {
                        buf.push(json!({ "method": e.method, "params": e.params }));
                        if buf.len() >= BATCH_MAX && !flush(&mut buf, &out) { return; }
                    } else if out.send(notification(e.method, e.params)).is_err() {
                        return;
                    }
                }
                Err(RecvError::Lagged(_)) => {}
                Err(RecvError::Closed) => { let _ = flush(&mut buf, &out); return; }
            },
            _ = tick.tick() => if !flush(&mut buf, &out) { return; },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(topic: &'static str, method: &'static str, n: u32) -> Event {
        Event {
            topic,
            method,
            params: json!({ "n": n }),
        }
    }

    #[tokio::test]
    async fn batches_process_events_at_200_and_filters_unsubscribed_topics() {
        let (tx, rx) = broadcast::channel(1024);
        let topics = Arc::new(Mutex::new(HashSet::from(["processes".to_string()])));
        let (out, mut inbox) = tokio::sync::mpsc::unbounded_channel();
        for i in 0..250 {
            tx.send(ev("processes", "event.process_started", i))
                .unwrap();
        }
        tx.send(ev("connections", "event.connection_opened", 0))
            .unwrap();
        tokio::spawn(forward(rx, topics, out));

        let mut sizes = Vec::new();
        let deadline = tokio::time::Instant::now() + Duration::from_millis(600);
        while let Ok(Some(n)) = tokio::time::timeout_at(deadline, inbox.recv()).await {
            assert_eq!(n.method, "event.batch");
            sizes.push(n.params.unwrap()["events"].as_array().unwrap().len());
        }
        assert_eq!(sizes.iter().sum::<usize>(), 250, "{sizes:?}");
        assert!(sizes.iter().all(|s| *s <= BATCH_MAX), "{sizes:?}");
        assert_eq!(sizes[0], BATCH_MAX, "first flush is size-triggered");
    }

    #[tokio::test]
    async fn non_batched_topics_are_sent_immediately() {
        let (tx, rx) = broadcast::channel(16);
        let topics = Arc::new(Mutex::new(HashSet::from(["health".to_string()])));
        let (out, mut inbox) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(forward(rx, topics, out));
        tx.send(ev("health", "event.health", 1)).unwrap();
        let n = tokio::time::timeout(Duration::from_millis(50), inbox.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(n.method, "event.health");
    }
}
