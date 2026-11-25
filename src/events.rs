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
    /// Normalized mailbox ID that emitted this event (empty when emitted on an unscoped bus).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub mailbox_id: String,
    pub source: EventSource,
    pub event: MailEvent,
}

/// Pluggable outbound bridge notified whenever a local event is published on [`EventBus`].
///
/// Remote nodes republish incoming events via [`EventBus::publish_remote_envelope`] so they
/// fan out locally to SSE `/v1/events`, IMAP `IDLE`, and Gmail `/watch` without re-triggering
/// the outbound bridge.
pub trait EventBridge: Send + Sync {
    /// Forward a locally published event envelope to remote nodes (non-blocking).
    fn publish(&self, envelope: &EventEnvelope);

    /// Short backend identifier for diagnostics.
    fn backend_name(&self) -> &'static str {
        "custom"
    }
}

/// Broadcast event bus with monotonic sequence IDs and bounded replay buffer for SSE `Last-Event-ID`.
#[derive(Clone)]
pub struct EventBus {
    tx: broadcast::Sender<EventEnvelope>,
    seq: Arc<AtomicU64>,
    replay: Arc<RwLock<VecDeque<EventEnvelope>>>,
    replay_capacity: usize,
    mailbox_id: String,
    bridge: Option<Arc<dyn EventBridge>>,
}

impl EventBus {
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_CHANNEL_CAPACITY, DEFAULT_REPLAY_CAPACITY)
    }

    pub fn with_mailbox(mailbox_id: &str) -> Self {
        let mut bus = Self::new();
        bus.mailbox_id = crate::config::normalize_mailbox_id(mailbox_id);
        bus
    }

    pub fn with_capacity(channel_capacity: usize, replay_capacity: usize) -> Self {
        let (tx, _) = broadcast::channel(channel_capacity.max(16));
        Self {
            tx,
            seq: Arc::new(AtomicU64::new(0)),
            replay: Arc::new(RwLock::new(VecDeque::with_capacity(replay_capacity))),
            replay_capacity,
            mailbox_id: String::new(),
            bridge: None,
        }
    }

    /// Attach a distributed [`EventBridge`] that forwards locally published events to peer nodes.
    pub fn with_bridge(mut self, bridge: Arc<dyn EventBridge>) -> Self {
        self.bridge = Some(bridge);
        self
    }

    /// Return the normalized mailbox ID attached to this bus handle (empty if unscoped).
    pub fn mailbox_id(&self) -> &str {
        &self.mailbox_id
    }

    /// Return a lightweight handle sharing the same broadcast channel, replay buffer, and bridge,
    /// tagged and filtered to `mailbox_id`.
    pub fn for_mailbox(&self, mailbox_id: &str) -> Self {
        Self {
            tx: self.tx.clone(),
            seq: self.seq.clone(),
            replay: self.replay.clone(),
            replay_capacity: self.replay_capacity,
            mailbox_id: crate::config::normalize_mailbox_id(mailbox_id),
            bridge: self.bridge.clone(),
        }
    }

    /// Publish an event to all active subscribers and record it in the replay buffer.
    pub fn publish(&self, source: EventSource, event: MailEvent) -> EventEnvelope {
        self.publish_for_mailbox(&self.mailbox_id, source, event)
    }

    /// Publish an event tagged with an explicit `mailbox_id` and forward to any attached bridge.
    pub fn publish_for_mailbox(
        &self,
        mailbox_id: &str,
        source: EventSource,
        event: MailEvent,
    ) -> EventEnvelope {
        let envelope = self.deliver_local(
            Utc::now(),
            crate::config::normalize_mailbox_id(mailbox_id),
            source,
            event,
        );
        if let Some(ref bridge) = self.bridge {
            bridge.publish(&envelope);
        }
        envelope
    }

    /// Republish an event received from a remote node into this node's local subscribers and
    /// replay buffer without re-forwarding it to the outbound [`EventBridge`].
    pub fn publish_remote_envelope(&self, envelope: EventEnvelope) -> EventEnvelope {
        self.deliver_local(
            envelope.timestamp,
            crate::config::normalize_mailbox_id(&envelope.mailbox_id),
            envelope.source,
            envelope.event,
        )
    }

    fn deliver_local(
        &self,
        timestamp: DateTime<Utc>,
        mailbox_id: String,
        source: EventSource,
        event: MailEvent,
    ) -> EventEnvelope {
        let id = self.seq.fetch_add(1, Ordering::Relaxed) + 1;
        let envelope = EventEnvelope {
            id,
            timestamp,
            mailbox_id,
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

    /// Return buffered events with `id > since_id`, scoped to `self.mailbox_id` when set, up to `limit`.
    pub fn events_since(&self, since_id: u64, limit: usize) -> Vec<EventEnvelope> {
        let Ok(buf) = self.replay.read() else {
            return Vec::new();
        };
        buf.iter()
            .filter(|e| {
                e.id > since_id
                    && (self.mailbox_id.is_empty()
                        || e.mailbox_id.is_empty()
                        || e.mailbox_id.eq_ignore_ascii_case(&self.mailbox_id))
            })
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
