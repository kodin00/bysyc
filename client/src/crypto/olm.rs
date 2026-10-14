//! Olm (pairwise double-ratchet) plumbing: one-time-key wire format, the
//! ciphertext transport codec, and the persistence records for peer
//! sessions. The session lifecycle itself lives in [`crate::crypto::Engine`].

use serde::{Deserialize, Serialize};
use vodozemac::Curve25519PublicKey;
use vodozemac::olm::{OlmMessage, Session, SessionPickle};

/// Render one uploadable one-time prekey as `"{key_id}:{b64_pubkey}"`.
///
/// The two halves are joined by the first `:`; base64 (standard or unpadded)
/// never contains `:` so the split is unambiguous. `key_id` is vodozemac's
/// internal `KeyId` (base64 of an incrementing counter) — it is opaque to the
/// server and exists so claims can be correlated; the engine itself matches
/// prekey messages by public key, not by id.
pub(crate) fn otk_wire_format(key_id: String, public: Curve25519PublicKey) -> String {
    format!("{key_id}:{}", public.to_base64())
}

/// Parse an OTK reference received back from a claim (or handed in by the
/// app) into `(key_id, public_key)`.
///
/// Accepts both `"{key_id}:{b64_pubkey}"` (what [`otk_wire_format`] emits and
/// what `POST /keys/otk` stores verbatim) and a bare `"{b64_pubkey}"`
/// (`ClaimedKeys.one_time_key` without an id prefix). A missing id is
/// reported as the empty string — it is informational only.
pub(crate) fn parse_otk(raw: &str) -> anyhow::Result<(String, Curve25519PublicKey)> {
    let raw = raw.trim();
    if raw.is_empty() {
        anyhow::bail!("empty one-time-key reference");
    }
    let (id, key) = match raw.split_once(':') {
        Some((id, key)) if !id.is_empty() && !key.is_empty() => (id.to_string(), key),
        // Whole string looks like a bare key (no colon, or a leading colon).
        _ => (String::new(), raw),
    };
    let public = Curve25519PublicKey::from_base64(key)
        .map_err(|e| anyhow::anyhow!("one-time key is not valid base64 Curve25519: {e}"))?;
    Ok((id, public))
}

/// Encode an [`OlmMessage`] into the single base64 string carried by
/// `MessageDto.content` / `MailboxItem.content`.
///
/// vodozemac gives `OlmMessage` a serde representation of
/// `{"type":0|1,"body":"<base64>"}`; we wrap that JSON in standard base64 so
/// the wire value stays an opaque b64 blob for the Instance.
pub(crate) fn olm_message_to_b64(message: &OlmMessage) -> anyhow::Result<String> {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let json = serde_json::to_vec(message)?;
    Ok(STANDARD.encode(json))
}

/// Decode the base64 string produced by [`olm_message_to_b64`].
pub(crate) fn olm_message_from_b64(b64: &str) -> anyhow::Result<OlmMessage> {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let json = STANDARD.decode(b64.trim())?;
    Ok(serde_json::from_slice(&json)?)
}

/// Parse a base64 Curve25519 identity key as carried by
/// `AccountBrief.identity_key`.
pub(crate) fn parse_identity_key(b64: &str) -> anyhow::Result<Curve25519PublicKey> {
    Curve25519PublicKey::from_base64(b64.trim())
        .map_err(|e| anyhow::anyhow!("invalid base64 Curve25519 identity key: {e}"))
}

/// One persisted Olm session: which peer it talks to, its id (for
/// diagnostics and dedup), and the encrypted pickle string.
#[derive(Serialize, Deserialize)]
pub(crate) struct OlmSessionRecord {
    /// Account id of the peer this session is with.
    pub peer_id: i64,
    /// Olm session id (hex string from vodozemac).
    pub session_id: String,
    /// `SessionPickle::encrypt(pickle_key)` output.
    pub pickle: String,
}

/// Unpickle a session record into a live [`Session`].
pub(crate) fn session_from_record(
    record: &OlmSessionRecord,
    key: &[u8; 32],
) -> anyhow::Result<Session> {
    let pickle = SessionPickle::from_encrypted(&record.pickle, key)
        .map_err(|e| anyhow::anyhow!("failed to decrypt olm session pickle: {e}"))?;
    Ok(Session::from_pickle(pickle))
}

/// Pickle a live [`Session`] into a storable record.
pub(crate) fn session_to_record(
    peer_id: i64,
    session: &Session,
    key: &[u8; 32],
) -> OlmSessionRecord {
    OlmSessionRecord {
        peer_id,
        session_id: session.session_id(),
        pickle: session.pickle().encrypt(key),
    }
}
