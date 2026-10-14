//! Megolm (group ratchet) plumbing: per-channel outbound sessions with the
//! rotation policy, per-(channel, sender) inbound sessions, and the queued
//! [`PendingShare`]s a rotation produces. Session lifecycle lives in
//! [`crate::crypto::Engine`].

use serde::{Deserialize, Serialize};
use vodozemac::megolm::{
    GroupSession, GroupSessionPickle, InboundGroupSession, InboundGroupSessionPickle,
    MegolmMessage, SessionConfig, SessionKey,
};

/// A Megolm session key queued to be sent to channel peers.
///
/// Produced when an outbound session is created or rotated
/// ([`crate::crypto::Engine::megolm_encrypt`]); the app drains the queue
/// ([`crate::crypto::Engine::drain_pending_shares`]) and mailboxes each
/// share to every peer, Olm-encrypted (see
/// [`crate::crypto::Engine::share_envelopes`]). Mirrors the fields of
/// [`crate::crypto::Envelope::SessionShare`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingShare {
    /// Channel the session encrypts.
    pub channel_id: i64,
    /// Megolm session id (Megolm messages do not carry one themselves).
    pub session_id: String,
    /// Base64 `SessionKey`; importing peers build an
    /// `InboundGroupSession` from it.
    pub session_key: String,
}

/// Rotate an outbound session after this many encrypted messages.
pub(crate) const ROTATE_AFTER_MESSAGES: u64 = 100;
/// Rotate an outbound session after this much wall-clock time (one week, ms).
pub(crate) const ROTATE_AFTER_MS: i64 = 7 * 24 * 60 * 60 * 1000;

/// A live outbound Megolm session plus its rotation bookkeeping.
pub(crate) struct OutboundSession {
    /// The vodozemac outbound group session.
    pub session: GroupSession,
    /// When the session was created, Unix epoch milliseconds.
    pub created_at_ms: i64,
    /// How many messages have been encrypted with it.
    pub message_count: u64,
}

impl OutboundSession {
    pub(crate) fn new(now_ms: i64) -> Self {
        Self {
            session: GroupSession::new(SessionConfig::version_1()),
            created_at_ms: now_ms,
            message_count: 0,
        }
    }

    /// Whether the rotation policy (ADR 0001: >100 messages or >1 week)
    /// says this session must be replaced before the next encryption.
    pub(crate) fn needs_rotation(&self, now_ms: i64) -> bool {
        self.message_count >= ROTATE_AFTER_MESSAGES
            || now_ms.saturating_sub(self.created_at_ms) >= ROTATE_AFTER_MS
    }

    /// The [`PendingShare`] describing this session to peers.
    pub(crate) fn pending_share(&self, channel_id: i64) -> PendingShare {
        PendingShare {
            channel_id,
            session_id: self.session.session_id(),
            session_key: self.session.session_key().to_base64(),
        }
    }
}

/// One persisted outbound session entry.
#[derive(Serialize, Deserialize)]
pub(crate) struct OutboundSessionRecord {
    /// Channel this session encrypts.
    pub channel_id: i64,
    /// `GroupSessionPickle::encrypt(pickle_key)` output.
    pub pickle: String,
    /// When the session was created, Unix epoch milliseconds.
    pub created_at_ms: i64,
    /// Messages encrypted so far.
    pub message_count: u64,
}

impl OutboundSession {
    pub(crate) fn to_record(&self, channel_id: i64, key: &[u8; 32]) -> OutboundSessionRecord {
        OutboundSessionRecord {
            channel_id,
            pickle: self.session.pickle().encrypt(key),
            created_at_ms: self.created_at_ms,
            message_count: self.message_count,
        }
    }
}

impl OutboundSessionRecord {
    pub(crate) fn to_live(&self, key: &[u8; 32]) -> anyhow::Result<OutboundSession> {
        let pickle = GroupSessionPickle::from_encrypted(&self.pickle, key)
            .map_err(|e| anyhow::anyhow!("failed to decrypt megolm outbound pickle: {e}"))?;
        Ok(OutboundSession {
            session: GroupSession::from_pickle(pickle),
            created_at_ms: self.created_at_ms,
            message_count: self.message_count,
        })
    }
}

/// One persisted inbound session entry, keyed by
/// (channel, sender, session_id) in the engine's map.
#[derive(Serialize, Deserialize)]
pub(crate) struct InboundSessionRecord {
    /// Channel the session decrypts.
    pub channel_id: i64,
    /// Account id of the sender who owns the outbound side.
    pub sender_id: i64,
    /// Megolm session id (for routing/dedup; Megolm messages lack it).
    pub session_id: String,
    /// `InboundGroupSessionPickle::encrypt(pickle_key)` output.
    pub pickle: String,
}

impl InboundSessionRecord {
    pub(crate) fn to_live(&self, key: &[u8; 32]) -> anyhow::Result<InboundGroupSession> {
        let pickle = InboundGroupSessionPickle::from_encrypted(&self.pickle, key)
            .map_err(|e| anyhow::anyhow!("failed to decrypt megolm inbound pickle: {e}"))?;
        Ok(InboundGroupSession::from_pickle(pickle))
    }
}

/// Build a live inbound session from a base64 `SessionKey` received in an
/// [`crate::crypto::Envelope::SessionShare`], checking that its session id
/// matches the id the sender claimed.
pub(crate) fn inbound_from_session_key(
    session_key_b64: &str,
    claimed_session_id: &str,
) -> anyhow::Result<InboundGroupSession> {
    let session_key = SessionKey::from_base64(session_key_b64)
        .map_err(|e| anyhow::anyhow!("invalid megolm session key: {e}"))?;
    let inbound = InboundGroupSession::new(&session_key, SessionConfig::version_1());
    let actual = inbound.session_id();
    if actual != claimed_session_id {
        anyhow::bail!(
            "megolm session key/id mismatch: share claims {claimed_session_id}, key is {actual}"
        );
    }
    Ok(inbound)
}

/// Pickle a live inbound session for storage.
pub(crate) fn inbound_to_record(
    channel_id: i64,
    sender_id: i64,
    session: &InboundGroupSession,
    key: &[u8; 32],
) -> InboundSessionRecord {
    InboundSessionRecord {
        channel_id,
        sender_id,
        session_id: session.session_id(),
        pickle: session.pickle().encrypt(key),
    }
}

/// Decode a base64 Megolm message.
pub(crate) fn megolm_message_from_b64(b64: &str) -> anyhow::Result<MegolmMessage> {
    MegolmMessage::from_base64(b64.trim())
        .map_err(|e| anyhow::anyhow!("invalid megolm message: {e}"))
}

/// Current wall-clock time in Unix epoch milliseconds.
pub(crate) fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outbound_rotation_policy_triggers_on_count_and_age() {
        let mut out = OutboundSession::new(1_000);
        assert!(!out.needs_rotation(1_500));
        out.message_count = ROTATE_AFTER_MESSAGES;
        assert!(out.needs_rotation(1_500), "message cap reached");
        out.message_count = 0;
        assert!(!out.needs_rotation(1_500));
        assert!(
            out.needs_rotation(1_000 + ROTATE_AFTER_MS),
            "one week elapsed"
        );
    }

    #[test]
    fn session_share_key_id_consistency() {
        // The session key we hand out must belong to the session id we claim.
        let out = OutboundSession::new(0);
        let share = out.pending_share(7);
        assert_eq!(share.channel_id, 7);
        assert_eq!(share.session_id, out.session.session_id());
        let inbound = inbound_from_session_key(&share.session_key, &share.session_id)
            .expect("key must match claimed id");
        assert_eq!(inbound.session_id(), share.session_id);
    }

    #[test]
    fn inbound_rejects_mismatched_session_id() {
        let out = OutboundSession::new(0);
        let share = out.pending_share(7);
        assert!(inbound_from_session_key(&share.session_key, "bogus-id").is_err());
    }
}
