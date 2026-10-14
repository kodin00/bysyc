//! The bysyc E2EE engine (ADR 0001): Olm for pairwise control channels,
//! Megolm per channel for content, both built on vodozemac.
//!
//! # Model
//!
//! - **Identity** — one Olm [`Account`] per device, pickled (encrypted with a
//!   key derived from the caller-supplied passphrase) into the injected
//!   [`KeyStore`] under the scope `olm_account`.
//! - **OTKs** — `uploadable_otks(n)` returns `"{key_id}:{b64_pubkey}"`
//!   strings for `POST /keys/otk`. Peers claim one through the server and
//!   use it to bootstrap an Olm session while we are offline.
//! - **Olm sessions** — one ratchet per peer (DMs + the control channel over
//!   which Megolm session keys travel). First message from a new peer is a
//!   prekey message; `olm_decrypt_from` transparently establishes the
//!   inbound session from it. Multiple sessions per peer are kept and tried
//!   newest-first.
//! - **Megolm sessions** — each sender keeps one outbound session per
//!   channel (rotated after 100 messages or one week). The session key is
//!   shared pairwise as an Olm-encrypted [`Envelope::SessionShare`] through
//!   the directed mailbox (the WhatsApp sender-key model). Receivers keep
//!   one inbound session per (channel, sender, session_id). Per ADR 0001
//!   newcomers only get history from their join point: the *current* session
//!   key is shared, never past ones.
//!
//! Megolm messages do not carry their session id, so the id travels
//! out-of-band: in every [`Envelope::SessionShare`], and (from the sender
//! side) as the `session_id` returned by [`Engine::megolm_encrypt`]. The
//! wire `MessageDto` stays an opaque base64 blob for the Instance.
//!
//! # App call sequence (for the client glue)
//!
//! Sending a chat message into channel `c`:
//!
//! 1. `engine.uploadable_otks(n)` at login; upload the returned strings.
//! 2. On first send: `let (session_id, ct) = engine.megolm_encrypt(c, json)`.
//!    If the channel's outbound session was just created (or rotated), the
//!    engine queued a [`PendingShare`].
//! 3. `engine.share_envelopes(c, peers)` — claim an OTK per unbootstrapped
//!    peer first; POST the returned ciphertexts to the mailbox. If a share
//!    was queued (creation/rotation), this sends its index-0 key so peers
//!    can read the message from step 2 too, then consumes the queue entry.
//!    Afterwards `engine.drain_pending_shares()` should return empty;
//!    leftovers mean a share nobody received yet — share again on restart.
//! 4. POST `SendMessageRequest { kind: Chat, content: ct, .. }`.
//!
//! Receiving: for a `MailboxItem`, `olm_decrypt_from`; if the plaintext is
//! an [`Envelope::SessionShare`], `megolm_import` it and ack. For a chat
//! `MessageDto`, `megolm_decrypt(channel, sender, session_id, content)` with
//! the newest session id known for that sender (pass `""` to try every
//! imported session of that sender — useful right after a rotation).

mod envelope;
mod keys;
mod megolm;
mod olm;

pub use envelope::Envelope;
pub use keys::KeyStore;
#[cfg(test)]
use keys::MemKeyStore;
pub use megolm::PendingShare;

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use anyhow::Context as _;
use vodozemac::megolm::InboundGroupSession;
use vodozemac::olm::{
    Account, AccountPickle, OlmMessage, Session, SessionConfig as OlmSessionConfig,
};

use keys::{
    SCOPE_MEGOLM_IN, SCOPE_MEGOLM_OUT, SCOPE_OLM_ACCOUNT, SCOPE_OLM_SESSIONS, SCOPE_PENDING_SHARES,
    STORE_SALT, derive_pickle_key,
};
use megolm::{
    InboundSessionRecord, OutboundSession, OutboundSessionRecord, inbound_from_session_key,
    inbound_to_record, megolm_message_from_b64, now_ms,
};
use olm::{
    OlmSessionRecord, olm_message_from_b64, olm_message_to_b64, parse_identity_key, parse_otk,
    session_to_record,
};

/// The E2EE engine. Interior-mutable and thread-safe (`Send + Sync`);
/// every operation picks a lock, mutates the live vodozemac state, and
/// re-pickles into the [`KeyStore`] before returning.
pub struct Engine {
    store: Arc<dyn KeyStore>,
    pickle_key: [u8; 32],
    inner: Mutex<EngineInner>,
}

struct EngineInner {
    account: Account,
    /// Olm sessions per peer account id, oldest first (newest tried first).
    olm_sessions: HashMap<i64, Vec<Session>>,
    /// Outbound Megolm session per channel id (we are the sender).
    megolm_out: HashMap<i64, OutboundSession>,
    /// Inbound Megolm sessions per (channel, sender, session id).
    megolm_in: HashMap<(i64, i64, String), InboundGroupSession>,
    /// Megolm session keys created/rotated but not yet mailed to peers.
    pending_shares: Vec<PendingShare>,
}

impl Engine {
    /// Create or restore the engine's identity.
    ///
    /// If the store already holds an account pickle it is decrypted with
    /// `passphrase`; a failure (usually a wrong passphrase or corrupted
    /// store) is an error rather than a silent fresh identity, so an account
    /// can never be silently replaced. Otherwise a new [`Account`] is
    /// generated and persisted.
    pub fn new(store: Arc<dyn KeyStore>, passphrase: String) -> anyhow::Result<Engine> {
        let pickle_key = derive_pickle_key(&passphrase, STORE_SALT);

        let account = match store.get(SCOPE_OLM_ACCOUNT) {
            Some(blob) => {
                let pickle =
                    String::from_utf8(blob).context("stored olm account pickle is not utf-8")?;
                let pickle = AccountPickle::from_encrypted(&pickle, &pickle_key).map_err(|e| {
                    anyhow::anyhow!("failed to decrypt stored olm account (wrong passphrase?): {e}")
                })?;
                Account::from_pickle(pickle)
            }
            None => Account::new(),
        };

        let olm_sessions = load_vec(&*store, SCOPE_OLM_SESSIONS)
            .context("loading olm session table")?
            .map(|records: Vec<OlmSessionRecord>| {
                let mut map: HashMap<i64, Vec<Session>> = HashMap::new();
                for record in records {
                    match olm::session_from_record(&record, &pickle_key) {
                        Ok(session) => map.entry(record.peer_id).or_default().push(session),
                        Err(e) => {
                            // One corrupt session must not brick the engine;
                            // the peer simply re-establishes on next contact.
                            eprintln!("bysyc crypto: dropping corrupt olm session: {e}");
                        }
                    }
                }
                map
            })
            .unwrap_or_default();

        let megolm_out = load_vec(&*store, SCOPE_MEGOLM_OUT)
            .context("loading megolm outbound table")?
            .map(|records: Vec<OutboundSessionRecord>| {
                let mut map = HashMap::new();
                for record in records {
                    match record.to_live(&pickle_key) {
                        Ok(session) => {
                            map.insert(record.channel_id, session);
                        }
                        Err(e) => eprintln!("bysyc crypto: dropping corrupt megolm outbound: {e}"),
                    }
                }
                map
            })
            .unwrap_or_default();

        let megolm_in = load_vec(&*store, SCOPE_MEGOLM_IN)
            .context("loading megolm inbound table")?
            .map(|records: Vec<InboundSessionRecord>| {
                let mut map = HashMap::new();
                for record in records {
                    match record.to_live(&pickle_key) {
                        Ok(session) => {
                            map.insert(
                                (
                                    record.channel_id,
                                    record.sender_id,
                                    record.session_id.clone(),
                                ),
                                session,
                            );
                        }
                        Err(e) => eprintln!("bysyc crypto: dropping corrupt megolm inbound: {e}"),
                    }
                }
                map
            })
            .unwrap_or_default();

        let pending_shares: Vec<PendingShare> =
            load_vec(&*store, SCOPE_PENDING_SHARES)?.unwrap_or_default();

        let engine = Engine {
            store,
            pickle_key,
            inner: Mutex::new(EngineInner {
                account,
                olm_sessions,
                megolm_out,
                megolm_in,
                pending_shares,
            }),
        };
        // Persist immediately so a fresh account survives even if the app
        // dies before the first real operation.
        {
            let inner = engine.lock();
            engine
                .persist(&inner)
                .context("persisting fresh engine state")?;
        }
        Ok(engine)
    }

    fn lock(&self) -> MutexGuard<'_, EngineInner> {
        // A poisoned mutex means a bug panic'd mid-mutation; refusing to
        // continue protects the pickled state from corruption.
        self.inner
            .lock()
            .expect("bysyc crypto engine mutex poisoned")
    }

    /// Base64 Curve25519 public identity key of this account.
    pub fn identity_key(&self) -> String {
        self.lock().account.identity_keys().curve25519.to_base64()
    }

    /// Generate `n` one-time prekeys and return them in the exact wire
    /// format `"{key_id}:{b64_pubkey}"` for `POST /keys/otk`.
    ///
    /// The keys are marked as published immediately (they leave the
    /// `one_time_keys` view), so each call hands out fresh keys. The private
    /// halves stay in the account until a peer's prekey message consumes
    /// them.
    pub fn uploadable_otks(&self, n: usize) -> Vec<String> {
        if n == 0 {
            return Vec::new();
        }
        let mut inner = self.lock();
        inner.account.generate_one_time_keys(n);
        let mut wire: Vec<String> = inner
            .account
            .one_time_keys()
            .into_iter()
            .map(|(key_id, public)| olm::otk_wire_format(String::from(key_id), public))
            .collect();
        wire.sort();
        inner.account.mark_keys_as_published();
        // Persisting is best-effort: the keys still work unpickled even if
        // this write fails, since the private halves live in the account.
        if let Err(e) = self.persist(&inner) {
            eprintln!("bysyc crypto: failed to persist account after OTK upload: {e}");
        }
        wire
    }

    /// Encrypt `plaintext` to one peer over Olm (DM content, or a Megolm
    /// `SessionShare` traveling through the mailbox).
    ///
    /// Reuses the newest existing session with the peer. Without one, a
    /// session is created from `peer_identity` + `peer_otk` (a claimed
    /// `"{key_id}:{b64}"` or bare b64 OTK); the first message is then a
    /// prekey message the peer unpacks with [`Engine::olm_decrypt_from`].
    /// vodozemac requires *some* prekey to establish a session, so a missing
    /// OTK is an error — claim one and retry (the protocol's fallback story
    /// is simply "peer's OTK pool is empty, try again later").
    ///
    /// Returns the base64 transport string for the mailbox/DM wire.
    pub fn olm_encrypt_to(
        &self,
        peer_id: i64,
        peer_identity: &str,
        peer_otk: Option<(String, String)>,
        plaintext: &str,
    ) -> anyhow::Result<String> {
        let mut inner = self.lock();
        let message = olm_encrypt(
            &mut inner,
            peer_id,
            peer_identity,
            peer_otk.as_ref(),
            plaintext,
        )?;
        self.persist(&inner)
            .context("persisting olm state after encrypt")?;
        olm_message_to_b64(&message)
    }

    /// Decrypt a base64 Olm transport string from `peer_id`.
    ///
    /// Tries existing sessions with the peer newest-first; a prekey message
    /// that no session matches establishes a new inbound session (consuming
    /// the matching one-time key). Fails per message — callers skip on
    /// error. The sender binding is authenticated: vodozemac rejects a
    /// prekey message whose embedded identity key differs from
    /// `peer_identity`.
    pub fn olm_decrypt_from(
        &self,
        peer_id: i64,
        peer_identity: &str,
        ciphertext_b64: &str,
    ) -> anyhow::Result<String> {
        let mut inner = self.lock();
        let message = olm_message_from_b64(ciphertext_b64)?;
        let plaintext = olm_decrypt(&mut inner, peer_id, peer_identity, &message)?;
        self.persist(&inner)
            .context("persisting olm state after decrypt")?;
        String::from_utf8(plaintext).context("olm plaintext is not utf-8")
    }

    /// Encrypt `plaintext` (an [`Envelope::Chat`] JSON in practice) into a
    /// channel with our outbound Megolm session, creating or rotating the
    /// session if needed. Returns `(session_id, base64_megolm_message)`.
    ///
    /// Creation and rotation each queue a [`PendingShare`]; the caller must
    /// drain them ([`Engine::drain_pending_shares`]) and mailbox the key to
    /// all channel peers, or nobody can decrypt.
    pub fn megolm_encrypt(
        &self,
        channel_id: i64,
        plaintext: &str,
    ) -> anyhow::Result<(String, String)> {
        let mut inner = self.lock();
        let now = now_ms();
        let needs_rotation = inner
            .megolm_out
            .get(&channel_id)
            .is_none_or(|out| out.needs_rotation(now));
        if needs_rotation {
            let fresh = OutboundSession::new(now);
            inner.pending_shares.push(fresh.pending_share(channel_id));
            inner.megolm_out.insert(channel_id, fresh);
        }
        let out = inner
            .megolm_out
            .get_mut(&channel_id)
            .expect("outbound session was just inserted");
        let session_id = out.session.session_id();
        let message = out.session.encrypt(plaintext);
        out.message_count += 1;
        self.persist(&inner)
            .context("persisting megolm outbound after encrypt")?;
        Ok((session_id, message.to_base64()))
    }

    /// Import a Megolm session key received in an [`Envelope::SessionShare`].
    ///
    /// The id claimed by the share is checked against the key (mismatch is
    /// an error). A share always carries the sender's *current* ratchet
    /// index — vodozemac exports `session_key()` at the index it is called —
    /// so importing is join-point semantics by construction (ADR 0001: no
    /// history before the share). If an inbound for the same session id
    /// already exists, the one that can decrypt from the earlier index wins
    /// (`compare`), so a late re-share never narrows decryptable history.
    pub fn megolm_import(
        &self,
        channel_id: i64,
        sender_id: i64,
        session_id: &str,
        session_key: &str,
    ) -> anyhow::Result<()> {
        use vodozemac::megolm::SessionOrdering;

        let mut incoming = inbound_from_session_key(session_key, session_id)?;
        let mut inner = self.lock();
        let key = (channel_id, sender_id, session_id.to_string());
        match inner.megolm_in.get_mut(&key) {
            Some(existing) => {
                // `Worse` = the existing session starts at a later index
                // than the incoming one → replace to widen history.
                if matches!(existing.compare(&mut incoming), SessionOrdering::Worse) {
                    inner.megolm_in.insert(key, incoming);
                }
            }
            None => {
                inner.megolm_in.insert(key, incoming);
            }
        }
        self.persist(&inner)
            .context("persisting megolm inbound after import")
    }

    /// Decrypt a base64 Megolm message from `sender_id` in `channel_id`.
    ///
    /// `session_id` selects the imported inbound session; pass an empty
    /// `session_id` to try every session imported from that sender (useful
    /// around rotations, when the message may predate the newest share).
    /// Per-message failures are returned as errors; callers skip.
    pub fn megolm_decrypt(
        &self,
        channel_id: i64,
        sender_id: i64,
        session_id: &str,
        ciphertext_b64: &str,
    ) -> anyhow::Result<String> {
        let mut inner = self.lock();
        let message = megolm_message_from_b64(ciphertext_b64)?;

        let decrypt_one =
            |session_id: &str, session: &mut InboundGroupSession| -> anyhow::Result<String> {
                let decrypted = session.decrypt(&message).map_err(|e| {
                    anyhow::anyhow!(
                        "megolm decrypt failed (channel {channel_id}, sender {sender_id}, \
                     session {session_id}): {e}"
                    )
                })?;
                String::from_utf8(decrypted.plaintext).context("megolm plaintext is not utf-8")
            };

        if !session_id.is_empty() {
            let key = &(channel_id, sender_id, session_id.to_string());
            let session = inner.megolm_in.get_mut(key).ok_or_else(|| {
                anyhow::anyhow!(
                    "no imported megolm session {session_id} for channel {channel_id} \
                     sender {sender_id}"
                )
            })?;
            return decrypt_one(session_id, session);
        }

        let mut candidates: Vec<&mut InboundGroupSession> = inner
            .megolm_in
            .iter_mut()
            .filter(|((ch, sender, _), _)| *ch == channel_id && *sender == sender_id)
            .map(|(_, session)| session)
            .collect();
        let mut last_err = anyhow::anyhow!(
            "no megolm session imported for channel {channel_id} sender {sender_id}"
        );
        for session in candidates.iter_mut() {
            match decrypt_one("", session) {
                Ok(text) => return Ok(text),
                Err(e) => last_err = e,
            }
        }
        Err(last_err)
    }

    /// Wrap the outbound Megolm session key of `channel_id` for each peer in
    /// `peers` as an Olm-encrypted [`Envelope::SessionShare`], creating the
    /// outbound session (without queueing a pending share — the caller is
    /// sharing right here) if the channel has none yet.
    ///
    /// If a queued [`PendingShare`] for this channel's current session is
    /// still waiting (creation or rotation), that exact key is sent: it was
    /// captured at index 0, before any message, so bootstrap peers can
    /// decrypt the whole session including its first message — otherwise the
    /// message that triggered the rotation would be unreadable to everyone.
    /// Once at least one peer received it, the queued entry is consumed, so
    /// a later call regenerates at the *current* ratchet index: a re-share
    /// for a late joiner, who per ADR 0001 only ever sees history from the
    /// join point onward. Peers that could not be reached in this call keep
    /// no entry — retrying them re-shares from the retry point.
    ///
    /// Returns `(peer_id, base64_olm_ciphertext)` per peer. A peer is
    /// *omitted* (rather than erroring the whole batch) when no session
    /// exists with it and its OTK could not be used — the caller retries
    /// those peers after claiming fresh keys. Do not include ourselves.
    pub fn share_envelopes(
        &self,
        channel_id: i64,
        peers: &[(i64, String, Option<(String, String)>)],
    ) -> Vec<(i64, String)> {
        let mut inner = self.lock();
        inner
            .megolm_out
            .entry(channel_id)
            .or_insert_with(|| OutboundSession::new(now_ms()));
        let Some(out) = inner.megolm_out.get(&channel_id) else {
            return Vec::new();
        };
        let current_sid = out.session.session_id();
        let share = inner
            .pending_shares
            .iter()
            .find(|p| p.channel_id == channel_id && p.session_id == current_sid)
            .cloned()
            .unwrap_or_else(|| out.pending_share(channel_id));
        let json = match (Envelope::SessionShare {
            channel_id: share.channel_id,
            session_id: share.session_id.clone(),
            session_key: share.session_key.clone(),
        })
        .to_json()
        {
            Ok(json) => json,
            Err(e) => {
                eprintln!("bysyc crypto: serializing SessionShare envelope failed: {e}");
                return Vec::new();
            }
        };

        let mut out_vec = Vec::with_capacity(peers.len());
        for (peer_id, identity, otk) in peers {
            match olm_encrypt(&mut inner, *peer_id, identity, otk.as_ref(), &json) {
                Ok(message) => {
                    if let Ok(b64) = olm_message_to_b64(&message) {
                        out_vec.push((*peer_id, b64));
                    }
                }
                Err(e) => eprintln!(
                    "bysyc crypto: sharing megolm session with peer {peer_id} failed: {e}"
                ),
            }
        }
        // The queued share was delivered to at least one peer: consume it so
        // a later `share_envelopes` for a newcomer regenerates at the current
        // index (join point) instead of re-sending the index-0 key. If
        // nobody could be reached, keep it queued for a retry.
        if !out_vec.is_empty() {
            inner
                .pending_shares
                .retain(|p| !(p.channel_id == channel_id && p.session_id == current_sid));
        }
        if let Err(e) = self.persist(&inner) {
            eprintln!("bysyc crypto: persisting after share failed: {e}");
        }
        out_vec
    }

    /// Take the queued [`PendingShare`]s (created by session creation or
    /// rotation in [`Engine::megolm_encrypt`], consumed by
    /// [`Engine::share_envelopes`] once delivered). Call it *after*
    /// `share_envelopes`: an entry left over here means a creation/rotation
    /// share nobody has received yet (e.g. the app crashed between encrypt
    /// and share; the queue is persisted, so on restart call
    /// `share_envelopes` again — the still-queued entry keeps its index-0
    /// key, hiding no message).
    pub fn drain_pending_shares(&self) -> Vec<PendingShare> {
        let mut inner = self.lock();
        let drained = std::mem::take(&mut inner.pending_shares);
        if let Err(e) = self.persist(&inner) {
            eprintln!("bysyc crypto: persisting drained shares failed: {e}");
        }
        drained
    }

    /// Encrypt a file's bytes with AES-256-GCM (12-byte nonce), as C4 does
    /// for attachments. Returns `(ciphertext_and_tag, key_b64, nonce_b64)`;
    /// ship the key and nonce inside an [`Envelope::File`] — never in the
    /// clear.
    pub fn encrypt_file(&self, bytes: &[u8]) -> anyhow::Result<(Vec<u8>, String, String)> {
        use aes_gcm::aead::{Aead, KeyInit};
        use aes_gcm::{Aes256Gcm, Key, Nonce};
        use base64::{Engine as _, engine::general_purpose::STANDARD};

        let key: [u8; 32] = rand::random();
        let nonce: [u8; 12] = rand::random();
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), bytes)
            .map_err(|e| anyhow::anyhow!("AES-256-GCM encryption failed: {e}"))?;
        Ok((ciphertext, STANDARD.encode(key), STANDARD.encode(nonce)))
    }

    /// Decrypt bytes produced by [`Engine::encrypt_file`]. Fails (per file)
    /// on a wrong key/nonce or tampered ciphertext.
    pub fn decrypt_file(
        &self,
        encrypted: &[u8],
        key_b64: &str,
        nonce_b64: &str,
    ) -> anyhow::Result<Vec<u8>> {
        use aes_gcm::aead::{Aead, KeyInit};
        use aes_gcm::{Aes256Gcm, Key, Nonce};
        use base64::{Engine as _, engine::general_purpose::STANDARD};

        let key = STANDARD
            .decode(key_b64.trim())
            .context("file key is not base64")?;
        let nonce = STANDARD
            .decode(nonce_b64.trim())
            .context("file nonce is not base64")?;
        if key.len() != 32 {
            anyhow::bail!("file key must be 32 bytes, got {}", key.len());
        }
        if nonce.len() != 12 {
            anyhow::bail!("file nonce must be 12 bytes, got {}", nonce.len());
        }
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
        cipher
            .decrypt(Nonce::from_slice(&nonce), encrypted)
            .map_err(|e| {
                anyhow::anyhow!("AES-256-GCM decryption failed (wrong key or tampered file?): {e}")
            })
    }

    /// Export the whole account identity as a passphrase-encrypted string
    /// (the ADR 0001 reinstall/recovery story). This is the Olm account only
    /// — Megolm channel state is per-device and is not carried over.
    pub fn export_identity(&self, passphrase: &str) -> anyhow::Result<String> {
        let export_key = derive_pickle_key(passphrase, keys::EXPORT_SALT);
        let inner = self.lock();
        let pickle = inner.account.pickle().encrypt(&export_key);
        Ok(serde_json::json!({ "v": 1, "pickle": pickle }).to_string())
    }

    /// Replace this engine's identity with an [`Engine::export_identity`]
    /// backup. Olm sessions bound to the previous identity are dropped
    /// (they would never decrypt); Megolm channel state is kept since
    /// sender sessions are identity-independent.
    pub fn import_identity(&self, export: &str, passphrase: &str) -> anyhow::Result<()> {
        let export_key = derive_pickle_key(passphrase, keys::EXPORT_SALT);
        let value: serde_json::Value =
            serde_json::from_str(export).context("identity export is not valid JSON")?;
        if value.get("v").and_then(serde_json::Value::as_i64) != Some(1) {
            anyhow::bail!("unsupported identity export version");
        }
        let pickle_str = value
            .get("pickle")
            .and_then(serde_json::Value::as_str)
            .context("identity export has no pickle field")?;
        let pickle = AccountPickle::from_encrypted(pickle_str, &export_key).map_err(|e| {
            anyhow::anyhow!("failed to decrypt identity export (wrong passphrase?): {e}")
        })?;
        let account = Account::from_pickle(pickle);

        let mut inner = self.lock();
        inner.account = account;
        inner.olm_sessions.clear();
        self.persist(&inner).context("persisting imported identity")
    }

    /// Pickle all engine state into the [`KeyStore`].
    fn persist(&self, inner: &EngineInner) -> anyhow::Result<()> {
        self.store.put(
            SCOPE_OLM_ACCOUNT,
            inner.account.pickle().encrypt(&self.pickle_key).as_bytes(),
        );

        let olm: Vec<OlmSessionRecord> = inner
            .olm_sessions
            .iter()
            .flat_map(|(peer_id, sessions)| {
                sessions
                    .iter()
                    .map(|s| session_to_record(*peer_id, s, &self.pickle_key))
            })
            .collect();
        put_json(&*self.store, SCOPE_OLM_SESSIONS, &olm)?;

        let out: Vec<OutboundSessionRecord> = inner
            .megolm_out
            .iter()
            .map(|(channel_id, out)| out.to_record(*channel_id, &self.pickle_key))
            .collect();
        put_json(&*self.store, SCOPE_MEGOLM_OUT, &out)?;

        let inb: Vec<InboundSessionRecord> = inner
            .megolm_in
            .iter()
            .map(|((channel_id, sender_id, _), session)| {
                inbound_to_record(*channel_id, *sender_id, session, &self.pickle_key)
            })
            .collect();
        put_json(&*self.store, SCOPE_MEGOLM_IN, &inb)?;

        put_json(&*self.store, SCOPE_PENDING_SHARES, &inner.pending_shares)?;
        Ok(())
    }
}

/// Core Olm encrypt used by [`Engine::olm_encrypt_to`] and
/// [`Engine::share_envelopes`]; mutates `inner` so callers must persist.
fn olm_encrypt(
    inner: &mut EngineInner,
    peer_id: i64,
    peer_identity: &str,
    peer_otk: Option<&(String, String)>,
    plaintext: &str,
) -> anyhow::Result<OlmMessage> {
    if let Some(session) = inner
        .olm_sessions
        .get_mut(&peer_id)
        .and_then(|v| v.last_mut())
    {
        return session
            .encrypt(plaintext)
            .map_err(|e| anyhow::anyhow!("olm encrypt failed: {e}"));
    }

    // No session yet: bootstrap one. vodozemac's 3DH requires the peer's
    // identity key AND a one-time (or fallback) key.
    let identity = parse_identity_key(peer_identity)?;
    let (_, one_time_key) = match peer_otk {
        Some((_, key)) => parse_otk(key)?,
        None => anyhow::bail!(
            "no olm session with peer {peer_id} and no one-time key claimed; \
             vodozemac requires a prekey to establish a session — claim an OTK \
             and retry"
        ),
    };
    let mut session = inner
        .account
        .create_outbound_session(OlmSessionConfig::version_1(), identity, one_time_key)
        .map_err(|e| anyhow::anyhow!("creating outbound olm session failed: {e}"))?;
    let message = session
        .encrypt(plaintext)
        .map_err(|e| anyhow::anyhow!("olm encrypt failed: {e}"))?;
    inner.olm_sessions.entry(peer_id).or_default().push(session);
    Ok(message)
}

/// Core Olm decrypt used by [`Engine::olm_decrypt_from`].
fn olm_decrypt(
    inner: &mut EngineInner,
    peer_id: i64,
    peer_identity: &str,
    message: &OlmMessage,
) -> anyhow::Result<Vec<u8>> {
    // Existing sessions first, newest first.
    if let Some(sessions) = inner.olm_sessions.get_mut(&peer_id) {
        for session in sessions.iter_mut().rev() {
            if let Ok(plaintext) = session.decrypt(message) {
                return Ok(plaintext);
            }
        }
    }

    // No session matched: a prekey message can still bootstrap one.
    if let OlmMessage::PreKey(prekey) = message {
        let identity = parse_identity_key(peer_identity)?;
        let created = inner
            .account
            .create_inbound_session(OlmSessionConfig::version_1(), identity, prekey)
            .map_err(|e| {
                anyhow::anyhow!("establishing inbound olm session from prekey message failed: {e}")
            })?;
        let session_id = created.session.session_id();
        let sessions = inner.olm_sessions.entry(peer_id).or_default();
        sessions.retain(|s| s.session_id() != session_id);
        sessions.push(created.session);
        return Ok(created.plaintext);
    }

    anyhow::bail!("no olm session with peer {peer_id} could decrypt the message")
}

/// Load a JSON-serialized `Vec<T>` from a store scope; `Ok(None)` when the
/// scope is empty (fresh install).
fn load_vec<T: serde::de::DeserializeOwned>(
    store: &dyn KeyStore,
    scope: &str,
) -> anyhow::Result<Option<Vec<T>>> {
    match store.get(scope) {
        None => Ok(None),
        Some(blob) => {
            Ok(Some(serde_json::from_slice(&blob).with_context(|| {
                format!("stored {scope} table is corrupt")
            })?))
        }
    }
}

fn put_json<T: serde::Serialize>(
    store: &dyn KeyStore,
    scope: &str,
    value: &T,
) -> anyhow::Result<()> {
    let blob = serde_json::to_vec(value).context("serializing engine state")?;
    store.put(scope, &blob);
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests — pure unit, alice+bob engines over an in-memory store.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use vodozemac::Curve25519PublicKey;

    const ALICE: i64 = 1;
    const BOB: i64 = 2;
    const CAROL: i64 = 3;
    const PASS: &str = "passphrase-for-tests";

    struct World {
        alice: Engine,
        bob: Engine,
        carol: Engine,
    }

    impl World {
        fn new() -> World {
            World {
                alice: Engine::new(Arc::new(MemKeyStore::default()), PASS.into()).unwrap(),
                bob: Engine::new(Arc::new(MemKeyStore::default()), PASS.into()).unwrap(),
                carol: Engine::new(Arc::new(MemKeyStore::default()), PASS.into()).unwrap(),
            }
        }
    }

    /// (a) OTK upload format is exactly "{key_id}:{b64_pubkey}".
    #[test]
    fn otk_upload_format() {
        let world = World::new();
        let otks = world.bob.uploadable_otks(2);
        assert_eq!(otks.len(), 2);
        let mut seen = std::collections::HashSet::new();
        for otk in &otks {
            let (id, key) = otk.split_once(':').expect("format is id:pubkey");
            assert!(!id.is_empty(), "key id must be non-empty: {otk}");
            Curve25519PublicKey::from_base64(key)
                .unwrap_or_else(|e| panic!("pubkey half must decode: {e} in {otk}"));
            assert!(seen.insert(otk.clone()), "otks must be unique: {otk}");
        }
        // Identity keys are non-empty base64 curve25519 values.
        assert!(!world.alice.identity_key().is_empty());
        assert_ne!(world.alice.identity_key(), world.bob.identity_key());
    }

    /// (b) Olm: prekey bootstrap, both directions, session reuse.
    #[test]
    fn olm_prekey_roundtrip_and_reuse() {
        let world = World::new();
        let alice_key = world.alice.identity_key();
        let bob_key = world.bob.identity_key();

        let otk = world.bob.uploadable_otks(1).pop().unwrap();
        let (id, key) = otk.split_once(':').unwrap();

        // Alice bootstraps with Bob's claimed OTK → prekey message.
        let ct = world
            .alice
            .olm_encrypt_to(BOB, &bob_key, Some((id.into(), key.into())), "hello bob")
            .unwrap();
        let pt = world
            .bob
            .olm_decrypt_from(ALICE, &alice_key, &ct)
            .expect("prekey message decrypts and establishes session");
        assert_eq!(pt, "hello bob");

        // Bob replies over the established session (no OTK needed).
        let reply = world
            .bob
            .olm_encrypt_to(ALICE, &alice_key, None, "hello alice")
            .unwrap();
        let pt = world.alice.olm_decrypt_from(BOB, &bob_key, &reply).unwrap();
        assert_eq!(pt, "hello alice");

        // Second alice→bob message reuses the session: still exactly one
        // session per peer on each side.
        let ct2 = world
            .alice
            .olm_encrypt_to(BOB, &bob_key, None, "still me")
            .unwrap();
        assert_eq!(
            world.bob.olm_decrypt_from(ALICE, &alice_key, &ct2).unwrap(),
            "still me"
        );
        assert_eq!(world.alice.lock().olm_sessions[&BOB].len(), 1);
        assert_eq!(world.bob.lock().olm_sessions[&ALICE].len(), 1);

        // A message from an unknown third party with garbage content fails.
        assert!(
            world
                .bob
                .olm_decrypt_from(ALICE + 5, &alice_key, &ct2)
                .is_err()
        );
    }

    /// (c) Megolm: share over the real Olm path, import, encrypt 3, decrypt
    /// all in order.
    #[test]
    fn megolm_share_import_and_ordered_decrypt() {
        let world = World::new();
        let alice_key = world.alice.identity_key();
        let bob_key = world.bob.identity_key();
        const CHANNEL: i64 = 7;

        // First send creates the outbound session and queues exactly one
        // pending share for the channel.
        let (sid0, ct0) = world
            .alice
            .megolm_encrypt(CHANNEL, r#"{"chat":{"text":"warmup","reply_to":null}}"#)
            .unwrap();

        // Full C3 flow (documented order — share, then drain): wrap the
        // queued share for bob via share_envelopes (uses bob's OTK since
        // there is no session yet), bob decrypts over Olm, imports.
        let otk = world.bob.uploadable_otks(1).pop().unwrap();
        let (otk_id, otk_key) = otk.split_once(':').unwrap();
        let shared = world.alice.share_envelopes(
            CHANNEL,
            &[(BOB, bob_key.clone(), Some((otk_id.into(), otk_key.into())))],
        );
        assert_eq!(shared.len(), 1, "the one peer must be shared with");
        let (peer, share_ct) = &shared[0];
        assert_eq!(*peer, BOB);
        let json = world
            .bob
            .olm_decrypt_from(ALICE, &alice_key, share_ct)
            .unwrap();
        let envelope = Envelope::from_json(&json).unwrap();
        let Envelope::SessionShare {
            channel_id,
            session_id,
            session_key,
        } = envelope
        else {
            panic!("expected a SessionShare envelope, got {json}");
        };
        assert_eq!(channel_id, CHANNEL);
        assert_eq!(session_id, sid0);
        world
            .bob
            .megolm_import(CHANNEL, ALICE, &session_id, &session_key)
            .expect("import validates id against key");

        // The warmup message (sent before the share reached bob in this
        // test) still decrypts: share_envelopes sends the *queued* share,
        // captured at creation (index 0), not a regenerated current-index
        // key. First-time receivers get the whole session.
        let got = world
            .bob
            .megolm_decrypt(CHANNEL, ALICE, &sid0, &ct0)
            .unwrap();
        assert!(got.contains("warmup"));
        // The delivered share consumed the queue entry.
        assert!(
            world.alice.drain_pending_shares().is_empty(),
            "share_envelopes consumes the queued share once delivered"
        );

        // Three ordered Chat envelopes.
        let texts = ["one", "two", "three"];
        for text in texts {
            let chat = Envelope::Chat {
                text: text.into(),
                reply_to: None,
            }
            .to_json()
            .unwrap();
            let (sid, ct) = world.alice.megolm_encrypt(CHANNEL, &chat).unwrap();
            assert_eq!(sid, sid0, "no rotation under the message cap");
            assert_eq!(
                world.bob.megolm_decrypt(CHANNEL, ALICE, &sid, &ct).unwrap(),
                chat
            );
        }

        // Empty session id tries all of the sender's sessions in the channel.
        let chat = Envelope::Chat {
            text: "anon".into(),
            reply_to: Some(9),
        }
        .to_json()
        .unwrap();
        let (_, ct) = world.alice.megolm_encrypt(CHANNEL, &chat).unwrap();
        assert_eq!(
            world.bob.megolm_decrypt(CHANNEL, ALICE, "", &ct).unwrap(),
            chat
        );

        // Bob cannot decrypt alice's session in a channel he never imported.
        let (_, ct_other) = world.alice.megolm_encrypt(CHANNEL + 1, &chat).unwrap();
        assert!(
            world
                .bob
                .megolm_decrypt(CHANNEL + 1, ALICE, &sid0, &ct_other)
                .is_err()
        );

        // Late joiner (ADR 0001): carol receives a share mid-stream. The key
        // is exported at the sender's current ratchet index, so history
        // before the join point stays unreadable while new messages decrypt.
        let carol_key = world.carol.identity_key();
        let carol_otk = world.carol.uploadable_otks(1).pop().unwrap();
        let (carol_otk_id, carol_otk_key) = carol_otk.split_once(':').unwrap();
        let shared = world.alice.share_envelopes(
            CHANNEL,
            &[(
                CAROL,
                carol_key,
                Some((carol_otk_id.into(), carol_otk_key.into())),
            )],
        );
        assert_eq!(shared.len(), 1, "the late joiner must be shared with");
        let (_, carol_share_ct) = &shared[0];
        let json = world
            .carol
            .olm_decrypt_from(ALICE, &alice_key, carol_share_ct)
            .unwrap();
        let Envelope::SessionShare {
            session_id,
            session_key,
            ..
        } = Envelope::from_json(&json).unwrap()
        else {
            panic!("expected a SessionShare envelope, got {json}");
        };
        assert_eq!(session_id, sid0);
        world
            .carol
            .megolm_import(CHANNEL, ALICE, &session_id, &session_key)
            .expect("mid-stream import validates");
        // Pre-join history is beyond carol's first known message index.
        assert!(
            world
                .carol
                .megolm_decrypt(CHANNEL, ALICE, &sid0, &ct0)
                .is_err(),
            "late joiner must not read pre-join history"
        );
        // Messages from the join point onward decrypt.
        let chat = Envelope::Chat {
            text: "welcome carol".into(),
            reply_to: None,
        }
        .to_json()
        .unwrap();
        let (sid, ct) = world.alice.megolm_encrypt(CHANNEL, &chat).unwrap();
        assert_eq!(sid, sid0, "still no rotation under the cap");
        assert_eq!(
            world
                .carol
                .megolm_decrypt(CHANNEL, ALICE, &sid, &ct)
                .unwrap(),
            chat
        );
    }

    /// (e) Pickle persistence: rebuild engines from the same store and keep
    /// decrypting; wrong passphrase is an error, not a new identity.
    #[test]
    fn pickle_persistence_across_restart() {
        let alice_store = Arc::new(MemKeyStore::default());
        let bob_store = Arc::new(MemKeyStore::default());
        let alice_key;
        let bob_key;
        let (sid, first_ct);

        {
            let alice = Engine::new(alice_store.clone(), PASS.into()).unwrap();
            let bob = Engine::new(bob_store.clone(), PASS.into()).unwrap();
            alice_key = alice.identity_key();
            bob_key = bob.identity_key();

            // Olm both ways.
            let otk = bob.uploadable_otks(1).pop().unwrap();
            let (id, key) = otk.split_once(':').unwrap();
            let ct = alice
                .olm_encrypt_to(
                    BOB,
                    &bob_key,
                    Some((id.into(), key.into())),
                    "before restart",
                )
                .unwrap();
            assert_eq!(
                bob.olm_decrypt_from(ALICE, &alice_key, &ct).unwrap(),
                "before restart"
            );
            let reply = bob
                .olm_encrypt_to(ALICE, &alice_key, None, "bob before")
                .unwrap();
            assert_eq!(
                alice.olm_decrypt_from(BOB, &bob_key, &reply).unwrap(),
                "bob before"
            );

            // Megolm session for channel 7, shared to bob.
            let (s, ct) = alice
                .megolm_encrypt(7, r#"{"chat":{"text":"pre","reply_to":null}}"#)
                .unwrap();
            sid = s;
            let share = alice.drain_pending_shares().pop().unwrap();
            bob.megolm_import(7, ALICE, &share.session_id, &share.session_key)
                .unwrap();
            first_ct = ct;
        }

        // Rebuild alice from the same store + passphrase.
        let alice = Engine::new(alice_store.clone(), PASS.into()).unwrap();
        let bob = Engine::new(bob_store, PASS.into()).unwrap();
        assert_eq!(alice.identity_key(), alice_key, "identity survives restart");

        // Olm state survived: bob's new message decrypts on the restarted
        // engine without any new handshake.
        let reply = bob
            .olm_encrypt_to(ALICE, &alice_key, None, "bob after")
            .unwrap();
        assert_eq!(
            alice.olm_decrypt_from(BOB, &bob_key, &reply).unwrap(),
            "bob after"
        );
        let more = alice
            .olm_encrypt_to(BOB, &bob_key, None, "alice after")
            .unwrap();
        assert_eq!(
            bob.olm_decrypt_from(ALICE, &alice_key, &more).unwrap(),
            "alice after"
        );

        // Megolm outbound survived: same session id continues, bob still
        // decrypts — including the pre-restart message.
        assert_eq!(
            bob.megolm_decrypt(7, ALICE, &sid, &first_ct)
                .unwrap()
                .contains("pre"),
            true
        );
        let chat = Envelope::Chat {
            text: "post".into(),
            reply_to: None,
        }
        .to_json()
        .unwrap();
        let (sid2, ct) = alice.megolm_encrypt(7, &chat).unwrap();
        assert_eq!(sid2, sid, "outbound continues the same megolm session");
        assert_eq!(bob.megolm_decrypt(7, ALICE, &sid, &ct).unwrap(), chat);

        // A wrong passphrase must not silently mint a new identity.
        let fresh_store = Arc::new(MemKeyStore::default());
        Engine::new(fresh_store.clone(), PASS.into()).unwrap();
        let err = Engine::new(fresh_store, "wrong passphrase".into());
        assert!(err.is_err(), "wrong passphrase must fail loudly");
    }

    /// Rotation: 100 messages then a new session id plus a fresh pending
    /// share.
    #[test]
    fn megolm_rotation_after_100_messages() {
        let alice = Engine::new(Arc::new(MemKeyStore::default()), PASS.into()).unwrap();
        let chat = r#"{"chat":{"text":"x","reply_to":null}}"#;
        let (sid_first, _) = alice.megolm_encrypt(7, chat).unwrap();
        assert_eq!(
            alice.drain_pending_shares().len(),
            1,
            "creation queues a share"
        );
        for _ in 1..100 {
            alice.megolm_encrypt(7, chat).unwrap();
        }
        assert!(alice.drain_pending_shares().is_empty(), "no rotation yet");

        // Message 101 rotates: the brand-new session's share is queued (the
        // first session's share was already drained above).
        let (sid_second, _) = alice.megolm_encrypt(7, chat).unwrap();
        assert_ne!(sid_first, sid_second);
        let pending = alice.drain_pending_shares();
        assert_eq!(
            pending.len(),
            1,
            "only the new session's share: {pending:?}"
        );
        assert_eq!(pending[0].session_id, sid_second);
        assert_eq!(pending[0].channel_id, 7);
    }

    /// File encryption roundtrip and tamper detection.
    #[test]
    fn file_encryption_roundtrip_and_tamper() {
        let engine = Engine::new(Arc::new(MemKeyStore::default()), PASS.into()).unwrap();
        let data = b"the bysyc attachment bytes \x00\x01\x02".repeat(64);
        let (ct, key, nonce) = engine.encrypt_file(&data).unwrap();
        assert_ne!(ct, data, "ciphertext must differ from plaintext");
        assert_eq!(engine.decrypt_file(&ct, &key, &nonce).unwrap(), data);

        let mut tampered = ct.clone();
        tampered[0] ^= 0xff;
        assert!(engine.decrypt_file(&tampered, &key, &nonce).is_err());
        // A valid-length but wrong key must error, not panic.
        assert!(
            engine
                .decrypt_file(&ct, &key_b64_flip(&key), &nonce)
                .is_err()
        );
        // Wrong-length key material is rejected with a clear error.
        assert!(engine.decrypt_file(&ct, &nonce, &nonce).is_err());
    }

    fn key_b64_flip(s: &str) -> String {
        let mut chars: Vec<char> = s.chars().collect();
        if chars[0] == 'A' {
            chars[0] = 'B';
        } else {
            chars[0] = 'A';
        }
        chars.into_iter().collect()
    }

    /// Identity export/import roundtrip.
    #[test]
    fn identity_export_import() {
        let store = Arc::new(MemKeyStore::default());
        let engine = Engine::new(store.clone(), PASS.into()).unwrap();
        let key = engine.identity_key();
        let export = engine.export_identity("backup-passphrase").unwrap();

        let restored = Engine::new(Arc::new(MemKeyStore::default()), PASS.into()).unwrap();
        assert_ne!(restored.identity_key(), key);
        restored
            .import_identity(&export, "backup-passphrase")
            .unwrap();
        assert_eq!(restored.identity_key(), key);
        assert!(restored.import_identity(&export, "wrong").is_err());
    }

    /// The engine is shareable across threads (egui + tokio glue).
    #[test]
    fn engine_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Engine>();
        assert_send_sync::<Arc<dyn KeyStore>>();
    }
}
