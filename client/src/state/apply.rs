//! Server-message application and the file-envelope helpers shared between
//! here and [`super::worker`].
//!
//! [`apply_server_msg`] is the single entry point through which every
//! server-pushed [`WsServerMsg`] mutates the world — the WS loop in
//! [`crate::net`] calls it, nothing else touches these fields ad hoc.
//! It only performs cheap mutations under the state lock: the world swap
//! and the roster/identity updates below, plus staging the expensive tail
//! of each event — Megolm/Olm decrypt, engine bootstrap (KDF), plaintext
//! and message-row writes — onto the crypto queue ([`super::worker::CryptoJob`]),
//! drained sequentially by the crypto worker with no lock held. Publishing
//! re-locks briefly, so a burst of incoming messages can no longer freeze
//! the UI thread, and per-channel decrypt order still matches arrival order
//! (one FIFO queue, one worker).
//!
//! The WS task stamps `MainState::net` itself right after a `Ready` (it owns
//! the handle). Message persistence happens in the caller *before* this runs
//! (the caller holds the store and the raw dto); lock order is
//! state → queue, then engine → store on the worker — never the reverse.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use bysyc_common::protocol::{MessageKind, WsServerBody, WsServerMsg};
use eframe::egui::Context;

use crate::crypto::{Engine, Envelope};
use crate::store::Store;

use super::worker::{CryptoJob, stage_crypto_job};
use super::{
    ClientState, ConnStatus, MAX_PENDING_NEWCOMERS, MAX_PENDING_SIGNALS, MainState, Phase,
    Selection, guard, push_capped,
};

/// Result of decrypting one message ciphertext into renderable text.
pub(super) enum Decrypted {
    Text(String),
    /// A File envelope (C4): the caller stashes it into
    /// [`MainState::file_meta`] and renders the "[file: …]" placeholder.
    File(Envelope),
    /// A Delete envelope: hide `target` (and the carrier).
    Deleted(i64),
    /// Could not decrypt or parse.
    Failed,
}

/// Megolm-decrypt `content` from `sender` in `channel` and map the envelope
/// to its renderable form. File envelopes come back whole so the caller can
/// keep their key/nonce; their display text is [`file_row_text`].
pub(super) fn decrypt_envelope_text(
    engine: &Engine,
    channel: i64,
    sender: i64,
    content: &str,
) -> Decrypted {
    let Ok(plaintext) = engine.megolm_decrypt(channel, sender, "", content) else {
        return Decrypted::Failed;
    };
    match serde_json::from_str::<Envelope>(&plaintext) {
        Ok(Envelope::Chat { text, .. }) => Decrypted::Text(text),
        Ok(fe @ Envelope::File { .. }) => Decrypted::File(fe),
        Ok(Envelope::Delete { target }) => Decrypted::Deleted(target),
        Ok(Envelope::SessionShare { .. }) | Err(_) => Decrypted::Failed,
    }
}

/// Persist a File envelope next to its message row so attachment rendering
/// survives a restart: `file_meta` is RAM-only, sender rows can never be
/// re-decrypted (the engine holds no Megolm self-import), and receiver rows
/// leave the `undecrypted` retry set once their plaintext lands. A failure
/// only costs the chip after the next restart, so it is logged, not
/// propagated.
pub(super) fn persist_file_envelope(store: &Arc<Mutex<Store>>, msg_id: i64, fe: &Envelope) {
    if let Ok(json) = fe.to_json()
        && let Err(e) = guard(store).set_file_envelope(msg_id, &json)
    {
        eprintln!("bysyc: persisting file envelope for message {msg_id} failed: {e}");
    }
}

/// File envelopes persisted for `channel_id` whose message row has no chip
/// stashed yet (`known` = the ids already in `file_meta`). The restart half
/// of [`MainState::backfill_plaintexts`]: persisted envelopes are the only
/// thing that can bring a chip back once the row carries its placeholder
/// plaintext. Store reads only — no state access.
pub(super) fn load_file_envelopes(
    store: &Arc<Mutex<Store>>,
    channel_id: i64,
    known: &HashSet<i64>,
) -> Vec<(i64, Envelope)> {
    let mut out = Vec::new();
    for (id, json) in guard(store).file_envelopes(channel_id) {
        if !known.contains(&id)
            && let Ok(fe) = Envelope::from_json(&json)
        {
            out.push((id, fe));
        }
    }
    out
}

/// Retry decryption for every still-NULL row of `channel_id` (rows cached
/// before the session share arrived), persisting plaintexts and file
/// envelopes as they land. Engine calls first, store writes batched after —
/// the engine pickles into the store while we hold no store lock (lock
/// order state → engine → store). Returns the plaintexts written and the
/// File envelopes stashed, for the caller to publish into `file_meta`.
/// Touches engine and store only — safe to run with no state lock held.
#[allow(clippy::type_complexity)]
pub(super) fn retry_undecrypted(
    engine: &Engine,
    own_id: i64,
    store: &Arc<Mutex<Store>>,
    channel_id: i64,
) -> (Vec<(i64, String)>, Vec<(i64, Envelope)>) {
    let rows = guard(store).undecrypted(channel_id);
    let mut texts: Vec<(i64, String)> = Vec::new();
    let mut files: Vec<(i64, Envelope)> = Vec::new();
    for (id, sender, content) in rows {
        if sender == own_id {
            continue; // own rows get their plaintext from the send task
        }
        match decrypt_envelope_text(engine, channel_id, sender, &content) {
            Decrypted::Text(text) => texts.push((id, text)),
            Decrypted::File(fe) => {
                let line = file_row_text(&fe);
                persist_file_envelope(store, id, &fe);
                files.push((id, fe));
                texts.push((id, line));
            }
            Decrypted::Deleted(_) | Decrypted::Failed => {}
        }
    }
    if !texts.is_empty() {
        let s = guard(store);
        for (id, text) in &texts {
            let _ = s.set_plaintext(*id, text);
        }
    }
    (texts, files)
}

/// One-liner shown for a File envelope row (also stored as the message
/// plaintext, so the row still reads sensibly after a restart).
pub fn file_row_text(fe: &Envelope) -> String {
    match fe {
        Envelope::File { name, size, .. } => {
            format!("[file: {name} ({})]", human_size(*size))
        }
        _ => "[file]".into(),
    }
}

/// Human-readable byte size: "0 B", "512 B", "2.0 KiB", "48.0 MiB", …
pub fn human_size(bytes: i64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let bytes = bytes.max(0); // negative sizes format as 0 B
    let mut size = bytes as f64;
    let mut unit = 0usize;
    while size >= 1024.0 && unit + 1 < UNITS.len() {
        size /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{size:.1} {}", UNITS[unit])
    }
}

/// Whether a file name looks like a directly renderable image, by extension
/// (png/jpg/jpeg/gif/webp, case-insensitive).
pub fn is_image_name(name: &str) -> bool {
    match name.rsplit_once('.') {
        Some((_, ext)) => matches!(
            ext.to_ascii_lowercase().as_str(),
            "png" | "jpg" | "jpeg" | "gif" | "webp"
        ),
        None => false,
    }
}

/// Apply one server-pushed WS message to the world and request a repaint.
/// Returns `true` when the message was `Ready`.
///
/// Only cheap mutations happen under the state lock: the world swap and the
/// roster/identity updates below, plus staging the expensive tail of each
/// event — Megolm/Olm decrypt, engine bootstrap (KDF), plaintext and
/// message-row writes — onto the crypto queue (`CryptoJob`), drained
/// sequentially by the crypto worker with no lock held. Publishing re-locks
/// briefly, so a burst of incoming messages can no longer freeze the UI
/// thread, and per-channel decrypt order still matches arrival order (one
/// FIFO queue, one worker).
///
/// The WS task stamps `MainState::net` itself right after a `Ready` (it owns
/// the handle). Message persistence happens in the caller *before* this runs
/// (the caller holds the store and the raw dto); lock order is
/// state → queue, then engine → store on the worker — never the reverse.
pub fn apply_server_msg(
    state: &Arc<Mutex<ClientState>>,
    store: &Arc<Mutex<Store>>,
    ctx: &Context,
    msg: WsServerMsg,
) -> bool {
    let mut st = guard(state);
    let generation = st.ws_generation;
    let q = Arc::clone(&st.jobs);
    let mut jobs: Vec<CryptoJob> = Vec::new();
    let mut was_ready = false;
    match msg.body {
        WsServerBody::Ready {
            account,
            friends,
            incoming_requests,
            outgoing_requests,
            guilds,
            dm_channels,
            mailbox,
        } => {
            was_ready = true;
            st.login_error = None;
            if let Phase::LoggedIn(m) = &mut st.phase {
                // Reconnect resync: replace the server-owned world, keep
                // local caches (messages, selection, voice, pending signals,
                // crypto state).
                m.online = friends.iter().filter(|f| f.online).map(|f| f.id).collect();
                m.account = account;
                m.friends = friends;
                m.incoming_requests = incoming_requests;
                m.outgoing_requests = outgoing_requests;
                m.guilds = guilds;
                m.dms = dm_channels;
                m.mailbox = mailbox;
                m.connection = ConnStatus::Online;
                m.validate_selection();
            } else {
                let boot = st.pending_engine.take();
                st.phase = Phase::LoggedIn(MainState::from_ready(
                    account,
                    friends,
                    incoming_requests,
                    outgoing_requests,
                    guilds,
                    dm_channels,
                    mailbox,
                    boot,
                ));
            }
            if let Some(m) = st.main_mut() {
                m.seed_world();
                // Load the user's audio device picks (set in the settings
                // view) so the call engine honours them when it next opens
                // its cpal streams. None => system default.
                m.audio_input = guard(store).audio_input();
                m.audio_output = guard(store).audio_output();
                // The crypto tail stages onto the worker, in the order the
                // synchronous path used to run it: the engine must exist
                // before the mailbox is processed (session shares ride in
                // it) — login/restore stage one in `pending_engine`, and if
                // it is missing (crash between WS connect and login task?)
                // the worker bootstraps from the local store — then the
                // mailbox, then a backfill per loaded channel (a share that
                // arrived while we were offline may unlock history cached
                // from the previous session).
                let username = m.account.username.clone();
                let need_boot = m.engine.is_none();
                let items = std::mem::take(&mut m.mailbox);
                let loaded: Vec<i64> = m.loaded.iter().copied().collect();
                if need_boot {
                    jobs.push(CryptoJob::EnsureEngine {
                        generation,
                        username,
                    });
                }
                if !items.is_empty() {
                    jobs.push(CryptoJob::Mailbox { generation, items });
                }
                for ch in loaded {
                    jobs.push(CryptoJob::Backfill {
                        generation,
                        channel_id: ch,
                    });
                }
            }
        }
        WsServerBody::Message(dto) => {
            // v1 has no chat-routed control payloads; drop those, stage the
            // rest — the worker decrypts, persists and publishes the row.
            if dto.kind != MessageKind::Control && st.main().is_some() {
                jobs.push(CryptoJob::Chat { generation, dto });
            }
        }
        WsServerBody::MessageDeleted {
            channel_id,
            message_id,
        } => {
            // Drop the row from the live cache and SQLite alike; the
            // deleter's own UI already did both when its DELETE returned
            // (the broadcast reaches them too), so this may be a repeat —
            // both removals are idempotent. A message we never had (a
            // channel opened after the delete) is a no-op on either side.
            // Queued (not applied inline) so the delete lands after any
            // still-pending decrypt of the same row: the worker is FIFO.
            jobs.push(CryptoJob::Deleted {
                generation,
                channel_id,
                message_id,
            });
        }
        WsServerBody::MailboxAppend(item) => {
            if let Some(m) = st.main_mut() {
                m.mailbox.push(item);
                let items = std::mem::take(&mut m.mailbox);
                jobs.push(CryptoJob::Mailbox { generation, items });
            }
        }
        WsServerBody::Presence { account_id, online } => {
            if let Some(m) = st.main_mut() {
                if online {
                    m.online.insert(account_id);
                } else {
                    m.online.remove(&account_id);
                }
                if let Some(f) = m.friends.iter_mut().find(|f| f.id == account_id) {
                    f.online = online;
                }
            }
        }
        WsServerBody::Typing {
            channel_id,
            account_id,
        } => {
            if let Some(m) = st.main_mut() {
                m.typing.insert(channel_id, (account_id, Instant::now()));
            }
        }
        WsServerBody::FriendRequested { from } => {
            if let Some(m) = st.main_mut() {
                m.identities.insert(from.id, from.identity_key.clone());
                if !m.incoming_requests.iter().any(|a| a.id == from.id) {
                    m.incoming_requests.push(from);
                }
            }
        }
        WsServerBody::FriendRequestAccepted { by } => {
            if let Some(m) = st.main_mut() {
                m.identities.insert(by.id, by.identity_key.clone());
                m.outgoing_requests.retain(|a| a.id != by.id);
                if !m.friends.iter().any(|a| a.id == by.id) {
                    if by.online {
                        m.online.insert(by.id);
                    }
                    m.friends.push(by);
                }
            }
        }
        WsServerBody::FriendRemoved { account_id } => {
            if let Some(m) = st.main_mut() {
                m.friends.retain(|a| a.id != account_id);
                m.dms.retain(|d| d.peer.id != account_id);
                m.online.remove(&account_id);
            }
        }
        WsServerBody::GuildJoined { guild } => {
            if let Some(m) = st.main_mut() {
                let roster = m.guild_members.entry(guild.id).or_default();
                roster.insert(guild.owner_id);
                roster.insert(m.account.id);
                match m.guilds.iter_mut().find(|g| g.id == guild.id) {
                    Some(existing) => *existing = guild,
                    None => m.guilds.push(guild),
                }
            }
        }
        WsServerBody::ChannelCreated { guild_id, channel } => {
            if let Some(m) = st.main_mut()
                && let Some(g) = m.guilds.iter_mut().find(|g| g.id == guild_id)
                && !g.channels.iter().any(|c| c.id == channel.id)
            {
                g.channels.push(channel);
            }
        }
        WsServerBody::ChannelDeleted {
            guild_id: _,
            channel_id,
        } => {
            if let Some(m) = st.main_mut() {
                for g in &mut m.guilds {
                    g.channels.retain(|c| c.id != channel_id);
                }
                if m.is_selected_channel(channel_id) {
                    m.selected = Selection::Friends;
                }
            }
        }
        WsServerBody::MemberJoined { guild_id, account } => {
            if let Some(m) = st.main_mut() {
                m.identities
                    .insert(account.id, account.identity_key.clone());
                m.guild_members
                    .entry(guild_id)
                    .or_default()
                    .insert(account.id);
                // Their session share may already sit in the mailbox.
                if !m.mailbox.is_empty() {
                    let items = std::mem::take(&mut m.mailbox);
                    jobs.push(CryptoJob::Mailbox { generation, items });
                }
                if account.id != m.account.id {
                    push_capped(
                        &mut m.pending_newcomers,
                        (guild_id, account.id),
                        MAX_PENDING_NEWCOMERS,
                    );
                }
            }
        }
        WsServerBody::MemberLeft {
            guild_id,
            account_id,
        } => {
            if let Some(m) = st.main_mut()
                && let Some(roster) = m.guild_members.get_mut(&guild_id)
            {
                roster.remove(&account_id);
            }
        }
        WsServerBody::VoiceState {
            channel_id,
            participants,
        } => {
            if let Some(m) = st.main_mut() {
                for p in &participants {
                    m.identities.insert(p.id, p.identity_key.clone());
                }
                if participants.is_empty() {
                    m.voice.remove(&channel_id); // empty snapshot = call ended
                } else {
                    m.voice.insert(channel_id, participants);
                }
            }
        }
        WsServerBody::CallSignal {
            call_id,
            from,
            kind,
        } => {
            if let Some(m) = st.main_mut() {
                push_capped(
                    &mut m.pending_signals,
                    (from, call_id, kind),
                    MAX_PENDING_SIGNALS,
                );
            }
        }
        WsServerBody::Error {
            code: _,
            reply_to: _,
            message,
        } => {
            if let Some(m) = st.main_mut() {
                m.notice = Some(message);
            }
        }
        // WsServerBody is #[non_exhaustive] and carries an `Unknown`
        // fallback variant (a newer server may emit a variant this client
        // does not know). The protocol contract is to log and ignore rather
        // than tear down the connection (see the protocol module docs).
        _ => {
            eprintln!("bysyc: ignoring unrecognized WsServerBody variant");
        }
    }
    drop(st);
    // Stage after releasing the state lock: spawning the worker (first job
    // of a burst) never happens under it. Job order = arrival order.
    for job in jobs {
        stage_crypto_job(&q, job, state, store, ctx);
    }
    ctx.request_repaint();
    was_ready
}

/// Unit coverage for [`apply_server_msg`]: feeds each `WsServerBody` variant
/// into a fresh `ClientState` with the worker gated off (see `NO_WORKER`) and
/// asserts both the synchronous `MainState` mutations and the exact
/// `CryptoJob`s staged. Staging is observable because the worker never runs;
/// real decryption is covered by the e2e + hermetic integration tests with a
/// live engine.
#[cfg(test)]
mod apply_tests {
    use super::*;
    use crate::state::EngineBoot;
    use crate::state::worker::{NO_WORKER, drain_staged};
    use bysyc_common::protocol::{
        AccountBrief, AccountInfo, CallSignalKind, ChannelInfo, ChannelKind, DmChannel, GuildInfo,
        MailboxItem, MessageDto,
    };

    fn acct(id: i64, name: &str) -> AccountInfo {
        AccountInfo {
            id,
            username: name.into(),
            identity_key: format!("identity-{id}"),
            created_at_ms: 0,
            is_admin: false,
        }
    }

    fn brief(id: i64, name: &str, online: bool) -> AccountBrief {
        AccountBrief {
            id,
            username: name.into(),
            identity_key: format!("identity-{id}"),
            online,
        }
    }

    fn chan(id: i64, guild: Option<i64>, kind: ChannelKind, name: &str) -> ChannelInfo {
        ChannelInfo {
            id,
            guild_id: guild,
            kind,
            name: name.into(),
        }
    }

    fn dto(id: i64, ch: i64, sender: i64, kind: MessageKind) -> MessageDto {
        MessageDto {
            id,
            channel_id: ch,
            sender_id: sender,
            kind,
            content: format!("ct-{id}"),
            reply_to: None,
            attachment: None,
            created_at_ms: id,
        }
    }

    fn guild(id: i64, owner: i64) -> GuildInfo {
        GuildInfo {
            id,
            name: format!("g{id}"),
            owner_id: owner,
            channels: vec![chan(id * 10 + 1, Some(id), ChannelKind::Text, "general")],
        }
    }

    fn dm(id: i64, peer: AccountBrief) -> DmChannel {
        DmChannel {
            channel: chan(id, None, ChannelKind::Dm, "dm"),
            peer,
        }
    }

    /// In-memory `KeyStore` so a real engine can be staged without touching
    /// disk (the crypto crate's `MemKeyStore` is test-gated to its own module).
    #[derive(Default)]
    struct TestKeys(std::sync::Mutex<std::collections::HashMap<String, Vec<u8>>>);

    impl crate::crypto::KeyStore for TestKeys {
        fn get(&self, scope: &str) -> Option<Vec<u8>> {
            self.0.lock().unwrap().get(scope).cloned()
        }
        fn put(&self, scope: &str, blob: &[u8]) {
            self.0.lock().unwrap().insert(scope.into(), blob.to_vec());
        }
        fn delete(&self, scope: &str) {
            self.0.lock().unwrap().remove(scope);
        }
    }

    /// A fresh world + gated worker. `NO_WORKER` is set on construction and
    /// never cleared (see its doc comment for why that is race-safe).
    struct Fixture {
        state: Arc<Mutex<ClientState>>,
        store: Arc<Mutex<Store>>,
        ctx: Context,
    }

    impl Fixture {
        fn new() -> Fixture {
            NO_WORKER.store(true, std::sync::atomic::Ordering::Relaxed);
            Fixture {
                state: Arc::new(Mutex::new(ClientState::new())),
                store: Arc::new(Mutex::new(
                    Store::open(std::path::Path::new(":memory:")).expect("open store"),
                )),
                ctx: Context::default(),
            }
        }

        fn apply(&self, body: WsServerBody) -> bool {
            apply_server_msg(&self.state, &self.store, &self.ctx, WsServerMsg { body })
        }

        /// Inspect the world read-only; `None` while Disconnected.
        fn with_main<T>(&self, f: impl FnOnce(&MainState) -> T) -> Option<T> {
            guard(&self.state).main().map(f)
        }
    }

    /// Pull every staged job out of the queue (the worker never ran, so these
    /// are exactly the jobs `apply_server_msg` pushed).
    fn drain_jobs(state: &Arc<Mutex<ClientState>>) -> Vec<CryptoJob> {
        let q = Arc::clone(&guard(state).jobs);
        drain_staged(&q)
    }

    fn ready_world() -> WsServerBody {
        WsServerBody::Ready {
            account: acct(1, "me"),
            friends: vec![brief(2, "friend", false)],
            incoming_requests: vec![],
            outgoing_requests: vec![],
            guilds: vec![guild(100, 2)],
            dm_channels: vec![dm(200, brief(2, "friend", false))],
            mailbox: vec![],
        }
    }

    /// Ready with no staged engine stages exactly one `EnsureEngine` job, and
    /// every synchronous part of the world swap applied: account, friends,
    /// guilds, DMs, online seeded from the friend's `online` flag, identities
    /// seeded from every visible brief, and the connection marked Online.
    #[test]
    fn ready_with_no_engine_stages_ensure_engine_and_swaps_world() {
        let f = Fixture::new();
        assert!(f.apply(ready_world()));

        assert_eq!(f.with_main(|m| m.account.id).unwrap_or(0), 1);
        assert_eq!(f.with_main(|m| m.friends.len()).unwrap_or(0), 1);
        assert_eq!(f.with_main(|m| m.friends[0].id).unwrap_or(0), 2);
        assert_eq!(f.with_main(|m| m.guilds.len()).unwrap_or(0), 1);
        assert_eq!(f.with_main(|m| m.guilds[0].id).unwrap_or(0), 100);
        assert_eq!(f.with_main(|m| m.dms.len()).unwrap_or(0), 1);
        assert_eq!(f.with_main(|m| m.dms[0].channel.id).unwrap_or(0), 200);
        // The friend's `online: false` seeds an empty online set.
        assert!(f.with_main(|m| m.online.is_empty()).unwrap_or(false));
        assert!(
            f.with_main(|m| matches!(m.connection, ConnStatus::Online))
                .unwrap_or(false)
        );
        // seed_world ran: self + friend + DM peer identities are known.
        assert_eq!(f.with_main(|m| m.identities.len()).unwrap_or(0), 2);
        assert!(
            f.with_main(|m| m.identities.contains_key(&1) && m.identities.contains_key(&2))
                .unwrap_or(false)
        );
        // Guild roster seeded with owner + self.
        assert!(
            f.with_main(|m| m
                .guild_members
                .get(&100)
                .is_some_and(|r| r.contains(&1) && r.contains(&2)))
                .unwrap_or(false)
        );

        // Exactly EnsureEngine; nothing to backfill (no loaded channels yet).
        let jobs = drain_jobs(&f.state);
        assert_eq!(
            jobs.len(),
            1,
            "Ready without an engine stages EnsureEngine only"
        );
        assert!(
            matches!(jobs[0], CryptoJob::EnsureEngine { generation: 0, ref username } if username == "me")
        );
    }

    /// Ready with a staged engine attaches it and stages NO EnsureEngine job.
    /// Proves the login→Ready hand-off: `pending_engine` is consumed.
    #[test]
    fn ready_with_staged_engine_skips_ensure_engine() {
        let f = Fixture::new();
        let engine = Engine::new(Arc::new(TestKeys::default()), "pass".into()).unwrap();
        {
            let mut st = guard(&f.state);
            st.pending_engine = Some(EngineBoot {
                engine: Arc::new(engine),
                outbound: HashSet::new(),
            });
        }
        f.apply(ready_world());
        assert!(
            f.with_main(|m| m.engine.is_some()).unwrap_or(false),
            "the staged engine must attach on Ready"
        );
        let jobs = drain_jobs(&f.state);
        assert!(
            jobs.iter()
                .all(|j| !matches!(j, CryptoJob::EnsureEngine { .. })),
            "no EnsureEngine when an engine was staged: {jobs:?}"
        );
    }

    /// Presence toggles both the online set and the friend's `online` flag;
    /// no crypto job is staged (the path is purely synchronous).
    #[test]
    fn presence_updates_online_set_and_friend_flag() {
        let f = Fixture::new();
        f.apply(ready_world());
        drain_jobs(&f.state);

        f.apply(WsServerBody::Presence {
            account_id: 2,
            online: true,
        });
        assert!(f.with_main(|m| m.online.contains(&2)).unwrap_or(false));
        assert!(
            f.with_main(|m| m.friends.iter().find(|x| x.id == 2).map(|x| x.online))
                .flatten()
                == Some(true)
        );

        f.apply(WsServerBody::Presence {
            account_id: 2,
            online: false,
        });
        assert!(!f.with_main(|m| m.online.contains(&2)).unwrap_or(true));
        assert!(
            f.with_main(|m| m.friends.iter().find(|x| x.id == 2).map(|x| x.online))
                .flatten()
                == Some(false)
        );
        assert!(
            drain_jobs(&f.state).is_empty(),
            "presence stages no crypto job"
        );
    }

    /// Typing records a per-channel entry; no job.
    #[test]
    fn typing_records_channel_entry() {
        let f = Fixture::new();
        f.apply(ready_world());
        drain_jobs(&f.state);

        f.apply(WsServerBody::Typing {
            channel_id: 200,
            account_id: 2,
        });
        assert_eq!(
            f.with_main(|m| m.typing.get(&200).map(|(who, _)| *who))
                .flatten(),
            Some(2)
        );
        assert!(drain_jobs(&f.state).is_empty());
    }

    /// A non-empty VoiceState snapshot replaces the channel's roster and
    /// learns every participant's identity; an empty snapshot clears it
    /// (call ended).
    #[test]
    fn voice_state_replaces_and_clears() {
        let f = Fixture::new();
        f.apply(ready_world());
        drain_jobs(&f.state);

        let p = vec![brief(3, "caller", true), brief(4, "other", true)];
        f.apply(WsServerBody::VoiceState {
            channel_id: 101,
            participants: p.clone(),
        });
        assert_eq!(
            f.with_main(|m| m.voice.get(&101).map(|v| v.len()))
                .flatten(),
            Some(2)
        );
        assert!(
            f.with_main(|m| m.identities.contains_key(&3) && m.identities.contains_key(&4))
                .unwrap_or(false)
        );

        f.apply(WsServerBody::VoiceState {
            channel_id: 101,
            participants: vec![],
        });
        assert!(
            f.with_main(|m| !m.voice.contains_key(&101))
                .unwrap_or(false),
            "empty snapshot clears the channel"
        );
    }

    /// CallSignal entries are capped at `MAX_PENDING_SIGNALS` (128); the
    /// oldest is dropped first once the cap is reached.
    #[test]
    fn call_signal_queue_is_capped_oldest_first() {
        let f = Fixture::new();
        f.apply(ready_world());
        drain_jobs(&f.state);

        for i in 0..MAX_PENDING_SIGNALS {
            f.apply(WsServerBody::CallSignal {
                call_id: 101,
                from: 2,
                kind: CallSignalKind::Hangup,
            });
            let _ = i;
        }
        assert_eq!(
            f.with_main(|m| m.pending_signals.len()).unwrap_or(0),
            MAX_PENDING_SIGNALS
        );
        let first_from = f
            .with_main(|m| m.pending_signals.first().map(|(from, _, _)| *from))
            .flatten();
        // One more push evicts the head (from == 2 in all of them, so check
        // the length stays capped instead).
        f.apply(WsServerBody::CallSignal {
            call_id: 101,
            from: 9,
            kind: CallSignalKind::Hangup,
        });
        assert_eq!(
            f.with_main(|m| m.pending_signals.len()).unwrap_or(0),
            MAX_PENDING_SIGNALS,
            "the cap holds"
        );
        assert!(
            f.with_main(|m| m.pending_signals.last().map(|(from, _, _)| *from))
                .flatten()
                == Some(9),
            "the newest push is at the tail"
        );
        // Pin `first_from` so it is read even when the cap push above made it
        // uninteresting — keeps the intent legible if MAX_PENDING_SIGNALS grows.
        let _ = first_from;
    }

    /// MemberJoined widens the guild roster, learns the identity, and queues
    /// a newcomer share (the joiner is not us). With an empty mailbox no
    /// Mailbox job is staged.
    #[test]
    fn member_join_widens_roster_and_queues_share() {
        let f = Fixture::new();
        f.apply(ready_world());
        drain_jobs(&f.state);

        f.apply(WsServerBody::MemberJoined {
            guild_id: 100,
            account: brief(7, "newcomer", false),
        });
        assert!(
            f.with_main(|m| m.guild_members.get(&100).is_some_and(|r| r.contains(&7)))
                .unwrap_or(false)
        );
        assert!(
            f.with_main(|m| m.identities.contains_key(&7))
                .unwrap_or(false)
        );
        assert_eq!(
            f.with_main(|m| m.pending_newcomers.clone())
                .unwrap_or_default(),
            vec![(100, 7)]
        );
        assert!(
            drain_jobs(&f.state).is_empty(),
            "empty mailbox → no Mailbox job from MemberJoined"
        );
    }

    /// A Chat message stages exactly one Chat job; a Control message is
    /// dropped (v1 has no chat-routed control payloads).
    #[test]
    fn message_stages_chat_job_and_drops_control() {
        let f = Fixture::new();
        f.apply(ready_world());
        drain_jobs(&f.state);

        f.apply(WsServerBody::Message(dto(10, 200, 2, MessageKind::Chat)));
        let jobs = drain_jobs(&f.state);
        assert_eq!(jobs.len(), 1);
        assert!(matches!(jobs[0], CryptoJob::Chat { generation: 0, ref dto } if dto.id == 10));

        f.apply(WsServerBody::Message(dto(11, 200, 2, MessageKind::Control)));
        assert!(
            drain_jobs(&f.state).is_empty(),
            "Control messages are dropped, never staged"
        );
    }

    /// MessageDeleted stages exactly one Deleted job (queued, not applied
    /// inline, so it lands after any in-flight decrypt of the same row).
    #[test]
    fn message_deleted_stages_deleted_job() {
        let f = Fixture::new();
        f.apply(ready_world());
        drain_jobs(&f.state);

        f.apply(WsServerBody::MessageDeleted {
            channel_id: 200,
            message_id: 42,
        });
        let jobs = drain_jobs(&f.state);
        assert_eq!(jobs.len(), 1);
        assert!(matches!(
            jobs[0],
            CryptoJob::Deleted {
                generation: 0,
                channel_id: 200,
                message_id: 42
            }
        ));
    }

    /// MailboxAppend takes the mailbox (drains it locally) and stages exactly
    /// one Mailbox job carrying the full item batch.
    #[test]
    fn mailbox_append_drains_and_stages_mailbox_job() {
        let f = Fixture::new();
        f.apply(ready_world());
        drain_jobs(&f.state);

        let item = MailboxItem {
            id: 900,
            sender_id: 2,
            content: "bWFpbA==".into(),
            created_at_ms: 1,
        };
        f.apply(WsServerBody::MailboxAppend(item.clone()));
        // The synchronous path takes the mailbox before staging, so the live
        // world holds nothing pending for the worker to drain.
        assert!(
            f.with_main(|m| m.mailbox.is_empty()).unwrap_or(false),
            "MailboxAppend takes the mailbox before staging the job"
        );
        let jobs = drain_jobs(&f.state);
        assert_eq!(jobs.len(), 1);
        match &jobs[0] {
            CryptoJob::Mailbox {
                generation: 0,
                items,
            } => {
                assert_eq!(items.len(), 1);
                assert_eq!(items[0].id, 900);
            }
            other => panic!("expected Mailbox job, got {other:?}"),
        }
    }
}
