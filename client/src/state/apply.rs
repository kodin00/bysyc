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

use super::{
    guard, push_capped, ClientState, ConnStatus, MainState, Phase, Selection,
    MAX_PENDING_NEWCOMERS, MAX_PENDING_SIGNALS,
};
use super::worker::{stage_crypto_job, CryptoJob};

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
    if let Ok(json) = fe.to_json() {
        if let Err(e) = guard(store).set_file_envelope(msg_id, &json) {
            eprintln!("bysyc: persisting file envelope for message {msg_id} failed: {e}");
        }
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
        if !known.contains(&id) {
            if let Ok(fe) = Envelope::from_json(&json) {
                out.push((id, fe));
            }
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
                    jobs.push(CryptoJob::EnsureEngine { generation, username });
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
            if let Some(m) = st.main_mut() {
                if let Some(g) = m.guilds.iter_mut().find(|g| g.id == guild_id) {
                    if !g.channels.iter().any(|c| c.id == channel.id) {
                        g.channels.push(channel);
                    }
                }
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
            if let Some(m) = st.main_mut() {
                if let Some(roster) = m.guild_members.get_mut(&guild_id) {
                    roster.remove(&account_id);
                }
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
                push_capped(&mut m.pending_signals, (from, call_id, kind), MAX_PENDING_SIGNALS);
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
