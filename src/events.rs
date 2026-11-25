use std::{
    collections::VecDeque,
    sync::{
        Arc, RwLock,
        atomic::{AtomicU64, Ordering},
    },
};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

const DEFAULT_CHANNEL_CAPACITY: usize = 1024;
const DEFAULT_REPLAY_CAPACITY: usize = 1024;

/// Origin of a `MailEvent`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EventSource {
    ResendInbound,
    ResendWebhook,
    SesInbound,
    GmailSync,
    Api,
    Mcp,
    Imap,
    System,
}

/// Unified domain event published across the server.
///
/// Consumed by `/v1/events` (SSE), embedded IMAP `IDLE`, and Gmail `/watch` push hooks.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum MailEvent {
    MessageReceived {
        message_id: String,
        thread_id: String,
        from: String,
        subject: String,
        snippet: String,
        labels: Vec<String>,
    },
    MessageSent {
        message_id: String,
        thread_id: String,
        to: Vec<String>,
        subject: String,
        resend_id: Option<String>,
        labels: Vec<String>,
    },
    MessageUpdated {
        message_id: String,
        thread_id: String,
        added_labels: Vec<String>,
        removed_labels: Vec<String>,
    },
    MessageDeleted {
        message_id: String,
        thread_id: String,
        labels: Vec<String>,
    },
    DraftCreated {
        draft_id: String,
        message_id: String,
        thread_id: String,
    },
    DeliveryStatus {
        message_id: String,
        resend_id: String,
        status: String,
        detail: Option<String>,
    },
    SyncCompleted {
        provider: String,
        messages_added: u64,
        messages_updated: u64,
        messages_deleted: u64,
        history_id: Option<String>,
    },
    ApprovalRequested {
        approval_id: String,
        reason: String,
        to: Vec<String>,
        subject: String,
        thread_id: Option<String>,
        draft_id: Option<String>,
        expires_at: DateTime<Utc>,
    },
    ApprovalResolved {
        approval_id: String,
        status: String,
        decided_by: Option<String>,
        sent_message_id: Option<String>,
    },
}

impl MailEvent {
    /// Snake-case event name matching the serde tag, useful for SSE `event:` headers and filters.
    pub fn event_type(&self) -> &'static str {
        match self {
            Self::MessageReceived { .. } => "message_received",
            Self::MessageSent { .. } => "message_sent",
            Self::MessageUpdated { .. } => "message_updated",
            Self::MessageDeleted { .. } => "message_deleted",
            Self::DraftCreated { .. } => "draft_created",
            Self::DeliveryStatus { .. } => "delivery_status",
            Self::SyncCompleted { .. } => "sync_completed",
            Self::ApprovalRequested { .. } => "approval_requested",
            Self::ApprovalResolved { .. } => "approval_resolved",
        }
    }

    /// Associated thread ID, if applicable.
    pub fn thread_id(&self) -> Option<&str> {
        match self {
            Self::MessageReceived { thread_id, .. }
            | Self::MessageSent { thread_id, .. }
            | Self::MessageUpdated { thread_id, .. }
            | Self::MessageDeleted { thread_id, .. }
            | Self::DraftCreated { thread_id, .. } => Some(thread_id.as_str()),
            Self::ApprovalRequested { thread_id, .. } => thread_id.as_deref(),
            Self::DeliveryStatus { .. }
            | Self::SyncCompleted { .. }
            | Self::ApprovalResolved { .. } => None,
        }
    }
}

/// Sequenced, timestamped event envelope delivered to subscribers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventEnvelope {
    pub id: u64,
    pub timestamp: DateTime<Utc>,
    pub source: EventSource,
    pub event: MailEvent,
}

/// Broadcast event bus with monotonic sequence IDs and bounded replay buffer for SSE `Last-Event-ID`.
#[derive(Clone)]
pub struct EventBus {
    tx: broadcast::Sender<EventEnvelope>,
    seq: Arc<AtomicU64>,
    replay: Arc<RwLock<VecDeque<EventEnvelope>>>,
    replay_capacity: usize,
}

impl EventBus {
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_CHANNEL_CAPACITY, DEFAULT_REPLAY_CAPACITY)
    }

    pub fn with_capacity(channel_capacity: usize, replay_capacity: usize) -> Self {
        let (tx, _) = broadcast::channel(channel_capacity.max(16));
        Self {
            tx,
            seq: Arc::new(AtomicU64::new(0)),
            replay: Arc::new(RwLock::new(VecDeque::with_capacity(replay_capacity))),
            replay_capacity,
        }
    }

    /// Publish an event to all active subscribers and record it in the replay buffer.
    pub fn publish(&self, source: EventSource, event: MailEvent) -> EventEnvelope {
        let id = self.seq.fetch_add(1, Ordering::Relaxed) + 1;
        let envelope = EventEnvelope {
            id,
            timestamp: Utc::now(),
            source,
            event,
        };
        if let Ok(mut buf) = self.replay.write() {
            if buf.len() >= self.replay_capacity {
                buf.pop_front();
            }
            buf.push_back(envelope.clone());
        }
        let _ = self.tx.send(envelope.clone());
        envelope
    }

    /// Subscribe to live events.
    pub fn subscribe(&self) -> broadcast::Receiver<EventEnvelope> {
        self.tx.subscribe()
    }

    /// Return buffered events with `id > since_id`, up to `limit`.
    pub fn events_since(&self, since_id: u64, limit: usize) -> Vec<EventEnvelope> {
        let Ok(buf) = self.replay.read() else {
            return Vec::new();
        };
        buf.iter()
            .filter(|e| e.id > since_id)
            .take(limit)
            .cloned()
            .collect()
    }

    /// Latest emitted sequence number (0 if none yet).
    pub fn latest_id(&self) -> u64 {
        self.seq.load(Ordering::Relaxed)
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}
