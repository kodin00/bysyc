//! Deferred crypto/store work: the staging queue and its one worker thread.
//!
//! Everything the WS receive path used to run while holding the state mutex
//! — Megolm/Olm decrypt, engine bootstrap (1024-round KDF), plaintext and
//! message-row writes — is staged here in arrival order and run sequentially
//! by one worker thread holding no lock. Results are published back under a
//! brief state lock; the single FIFO queue keeps per-channel decrypt order
//! identical to arrival order. See [`super`] for the entry point that stages
//! jobs ([`stage_crypto_job`]) and [`super::apply`] for the helpers this
//! worker calls into (decrypt, file envelopes).

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};

use bysyc_common::protocol::{MailboxItem, MessageDto, WsClientBody, WsClientMsg};
use eframe::egui::Context;

use crate::crypto::Envelope;
use crate::store::Store;

use super::apply::{
    Decrypted, decrypt_envelope_text, file_row_text, load_file_envelopes, persist_file_envelope,
    retry_undecrypted,
};
use super::{ClientState, MAILBOX_STALE_MS, MAX_OUTBOX_ACKS, guard, now_ms, push_capped};

/// Deferred crypto/store work. Jobs are staged in arrival order, executed
/// sequentially by one worker thread holding no locks, and published back
/// under a brief state lock; the single FIFO keeps decrypt order per channel
/// identical to arrival order.
pub(super) enum CryptoJob {
    /// Megolm-decrypt one incoming chat message, persist its plaintext (or
    /// apply its Delete envelope), then insert the row into the live cache.
    Chat { generation: u64, dto: MessageDto },
    /// Hide a deleted message in the store and live cache. Queued (not
    /// applied inline) so it lands after any still-pending decrypt of the
    /// same row; both removals are idempotent.
    Deleted {
        generation: u64,
        channel_id: i64,
        message_id: i64,
    },
    /// Olm-decrypt + import a batch of mailbox items, ack what was consumed
    /// and retry-decrypt every channel a fresh share unlocked.
    Mailbox {
        generation: u64,
        items: Vec<MailboxItem>,
    },
    /// Bootstrap the engine from the local store when login staged none
    /// (crash between WS connect and login task). The KDF plus unpickling
    /// of every session is far too slow for the state lock the UI needs
    /// every frame.
    EnsureEngine { generation: u64, username: String },
    /// Retry decryption for one loaded channel's cached rows and rebuild
    /// its attachment chips from persisted envelopes.
    Backfill { generation: u64, channel_id: i64 },
}

/// The staging queue plus a one-worker latch. Locking is leaf-level:
/// staging happens while the state lock may be held (order state → queue);
/// the worker takes the queue lock only to pop or to stage a follow-up,
/// never while holding anything else, so the two locks never nest the
/// other way around.
#[derive(Default)]
pub(super) struct CryptoQueue {
    inner: Mutex<CryptoQueueInner>,
}

#[derive(Default)]
struct CryptoQueueInner {
    queue: VecDeque<CryptoJob>,
    /// Whether a worker thread currently exists. Set under `inner` before
    /// spawning; cleared by the worker when it observes the queue empty
    /// under the same lock — so a job staged in any interleaving either
    /// reaches the running worker or spawns a fresh one.
    worker_alive: bool,
}

/// Append `job` and make sure exactly one worker thread is draining the
/// queue (see [`CryptoWorker::run`] for the empty-exit protocol).
pub(super) fn stage_crypto_job(
    q: &Arc<CryptoQueue>,
    job: CryptoJob,
    state: &Arc<Mutex<ClientState>>,
    store: &Arc<Mutex<Store>>,
    ctx: &Context,
) {
    let spawn = {
        let mut inner = guard(&q.inner);
        inner.queue.push_back(job);
        if inner.worker_alive {
            false
        } else {
            inner.worker_alive = true;
            true
        }
    };
    if spawn {
        let q = Arc::clone(q);
        let state = Arc::clone(state);
        let store = Arc::clone(store);
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            CryptoWorker {
                q,
                state,
                store,
                ctx,
            }
            .run()
        });
    }
}

/// Everything a worker thread needs: the queue (for the follow-up jobs it
/// stages itself) plus the world handles it gathers from and publishes to.
struct CryptoWorker {
    q: Arc<CryptoQueue>,
    state: Arc<Mutex<ClientState>>,
    store: Arc<Mutex<Store>>,
    ctx: Context,
}

impl CryptoWorker {
    /// Pop and run jobs until the queue is empty, then exit (the latch
    /// clears under the queue lock, atomically with the empty check, so an
    /// idle session holds no thread and nothing staged can be stranded).
    /// A panicking job is caught and logged rather than killing the worker:
    /// the latch would otherwise strand every job staged behind it.
    fn run(&self) {
        loop {
            let job = {
                let mut inner = guard(&self.q.inner);
                match inner.queue.pop_front() {
                    Some(job) => job,
                    None => {
                        inner.worker_alive = false;
                        return;
                    }
                }
            };
            if let Err(p) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.job(job)))
            {
                eprintln!("bysyc: crypto worker job panicked: {p:?}");
            }
        }
    }

    /// Dispatch one job. Every handler re-checks the generation under its
    /// gather lock and drops stale work before touching the engine or
    /// store (sign-out bumped the generation) — except `deleted`, whose
    /// idempotent store write always applies, exactly as this branch's
    /// store delete ran unconditionally before the worker existed.
    fn job(&self, job: CryptoJob) {
        match job {
            CryptoJob::Chat { generation, dto } => self.chat(generation, dto),
            CryptoJob::Deleted {
                generation,
                channel_id,
                message_id,
            } => self.deleted(generation, channel_id, message_id),
            CryptoJob::Mailbox { generation, items } => self.mailbox(generation, items),
            CryptoJob::EnsureEngine {
                generation,
                username,
            } => self.ensure_engine(generation, username),
            CryptoJob::Backfill {
                generation,
                channel_id,
            } => self.backfill(generation, channel_id),
        }
    }

    /// What `apply_chat_message` used to do under the state lock, now with
    /// the decrypt outside it: Megolm-decrypt, persist the plaintext (or
    /// apply the Delete), then a brief re-lock to publish the row (or the
    /// delete's effect) and the file chip, plus a repaint. Our own sends
    /// skip decryption: the send task already stored the plaintext from
    /// the REST response, and the engine deliberately holds no
    /// self-import. Undecryptable rows get a terminal "[undecryptable]"
    /// marker; with no engine the row stays NULL and renders as
    /// "[encrypted]" until backfill can retry it.
    fn chat(&self, generation: u64, dto: MessageDto) {
        let msg_id = dto.id;
        let channel_id = dto.channel_id;
        let (engine, own_id) = {
            let st = guard(&self.state);
            if st.ws_generation != generation {
                return;
            }
            let Some(m) = st.main() else { return };
            (m.engine.clone(), m.account.id)
        };
        // The WS receive loop batches raw inserts; this job can beat the
        // batch to the store. Put the row in first — INSERT OR IGNORE keeps
        // this a no-op when the batch already flushed, and never clobbers a
        // plaintext another path stored.
        {
            let s = guard(&self.store);
            let _ = s.insert_message_page(std::slice::from_ref(&dto));
        }
        let mut file = None;
        let mut deleted = None;
        let show = if dto.sender_id == own_id {
            true
        } else if let Some(engine) = engine {
            match decrypt_envelope_text(&engine, channel_id, dto.sender_id, &dto.content) {
                Decrypted::Text(text) => {
                    guard(&self.store).set_plaintext(msg_id, &text).ok();
                    true
                }
                Decrypted::File(fe) => {
                    // The attachment's key/nonce live only in this
                    // envelope: stash it (C4's UI renders from
                    // `file_meta`), persist it so the row survives a
                    // restart, then store the placeholder text like any
                    // other row.
                    let line = file_row_text(&fe);
                    persist_file_envelope(&self.store, msg_id, &fe);
                    guard(&self.store).set_plaintext(msg_id, &line).ok();
                    file = Some(fe);
                    true
                }
                Decrypted::Deleted(target) => {
                    let s = guard(&self.store);
                    let _ = s.delete_message(target);
                    let _ = s.delete_message(msg_id); // carrier never renders again
                    deleted = Some(target);
                    false
                }
                Decrypted::Failed => {
                    guard(&self.store)
                        .set_plaintext(msg_id, "[undecryptable]")
                        .ok();
                    true
                }
            }
        } else {
            true // no engine yet: row stays NULL, renders "[encrypted]"
        };
        let repaint = {
            let mut st = guard(&self.state);
            if st.ws_generation != generation {
                return;
            }
            match st.main_mut() {
                Some(m) => {
                    if let Some(target) = deleted {
                        m.remove_message(channel_id, target);
                    }
                    if show {
                        m.append_message(dto);
                        if !m.is_selected_channel(channel_id) {
                            m.unread.insert(channel_id);
                        }
                    }
                    if let Some(fe) = file {
                        m.file_meta.insert(msg_id, fe);
                    }
                    true
                }
                None => false,
            }
        };
        if repaint {
            self.ctx.request_repaint();
        }
    }

    /// Hide a deleted message: the store write first (idempotent), then a
    /// brief re-lock to drop the live row. The queue guarantees this runs
    /// after any still-pending decrypt of the same row.
    fn deleted(&self, generation: u64, channel_id: i64, message_id: i64) {
        let _ = guard(&self.store).delete_message(message_id);
        let repaint = {
            let mut st = guard(&self.state);
            if st.ws_generation != generation {
                return;
            }
            match st.main_mut() {
                Some(m) => {
                    m.remove_message(channel_id, message_id);
                    true
                }
                None => false,
            }
        };
        if repaint {
            self.ctx.request_repaint();
        }
    }

    /// What `process_mailbox` used to do under the state lock, now with the
    /// Olm work outside it: Olm-decrypt each item, expect an
    /// [`Envelope::SessionShare`], import the Megolm key. Items whose
    /// sender identity is not known yet are kept (not acked) for a later
    /// retry; stale items (older than [`MAILBOX_STALE_MS`]) and
    /// undecryptable/malformed ones are acked and dropped — the mailbox
    /// must never block. Publish re-locks briefly to return the keeps; acks
    /// flush straight out when the socket handle exists, else they queue
    /// in [`MainState::outbox_acks`] for the WS loop's follow-up drain
    /// (there is no handle at the first Ready yet).
    fn mailbox(&self, generation: u64, items: Vec<MailboxItem>) {
        let (engine, identities) = {
            let st = guard(&self.state);
            if st.ws_generation != generation {
                return;
            }
            let Some(m) = st.main() else { return };
            let mut identities = HashMap::with_capacity(items.len());
            for it in &items {
                if let Some(key) = m.identities.get(&it.sender_id) {
                    identities.insert(it.sender_id, key.clone());
                }
            }
            (m.engine.clone(), identities)
        };
        let mut keep = Vec::new();
        let mut acks: Vec<i64> = Vec::new();
        let mut imported: Vec<i64> = Vec::new();
        if let Some(engine) = engine {
            let now = now_ms();
            for item in items {
                if now.saturating_sub(item.created_at_ms) > MAILBOX_STALE_MS {
                    acks.push(item.id);
                    continue;
                }
                let Some(identity) = identities.get(&item.sender_id) else {
                    keep.push(item); // identity unknown yet; retry once learned
                    continue;
                };
                match engine.olm_decrypt_from(item.sender_id, identity, &item.content) {
                    Ok(plaintext) => match serde_json::from_str::<Envelope>(&plaintext) {
                        Ok(Envelope::SessionShare {
                            channel_id,
                            session_id,
                            session_key,
                        }) => {
                            match engine.megolm_import(
                                channel_id,
                                item.sender_id,
                                &session_id,
                                &session_key,
                            ) {
                                Ok(()) => imported.push(channel_id),
                                Err(e) => {
                                    eprintln!(
                                        "bysyc: megolm import failed (channel {channel_id}): {e}"
                                    )
                                }
                            }
                            acks.push(item.id);
                        }
                        _ => acks.push(item.id), // not a share → malformed for us: skip
                    },
                    Err(_) => acks.push(item.id), // undecryptable: ack + skip
                }
            }
        } else {
            keep = items; // no engine: keep everything, retry after bootstrap
        }
        let flush_direct;
        {
            let mut st = guard(&self.state);
            if st.ws_generation != generation {
                return;
            }
            let Some(m) = st.main_mut() else { return };
            m.mailbox.extend(keep);
            flush_direct = m.net.is_some();
            if !flush_direct {
                for &id in &acks {
                    push_capped(&mut m.outbox_acks, id, MAX_OUTBOX_ACKS);
                }
            }
        }
        if flush_direct && !acks.is_empty() {
            let handle = guard(&self.state).main().and_then(|m| m.net.clone());
            let sent = match handle {
                Some(h) => h
                    .out
                    .try_send(WsClientMsg {
                        id: crate::net::next_msg_id(),
                        body: WsClientBody::AckMailbox { ids: acks.clone() },
                    })
                    .is_ok(),
                None => false,
            };
            if !sent {
                let mut st = guard(&self.state);
                if let Some(m) = st.main_mut() {
                    for &id in &acks {
                        push_capped(&mut m.outbox_acks, id, MAX_OUTBOX_ACKS);
                    }
                }
            }
        }
        // A freshly imported session may unlock history we already cached —
        // stage a backfill behind whatever is already queued.
        for channel_id in imported {
            stage_crypto_job(
                &self.q,
                CryptoJob::Backfill {
                    generation,
                    channel_id,
                },
                &self.state,
                &self.store,
                &self.ctx,
            );
        }
        if !acks.is_empty() {
            self.ctx.request_repaint();
        }
    }

    /// Build the engine when login staged none: the KDF, unpickling of
    /// every session and the initial re-persist all happen on this thread;
    /// a brief re-lock then attaches the engine (and its persisted outbound
    /// set) or surfaces the failure notice.
    fn ensure_engine(&self, generation: u64, username: String) {
        if guard(&self.state).ws_generation != generation {
            return; // session superseded — no KDF for a dead world
        }
        let boot = crate::store::bootstrap_engine(&self.store, &username);
        let repaint = {
            let mut st = guard(&self.state);
            if st.ws_generation != generation {
                return;
            }
            match st.main_mut() {
                Some(m) if m.engine.is_none() => match boot {
                    Ok((engine, outbound)) => {
                        m.engine = Some(engine);
                        m.outbound.extend(outbound);
                        true
                    }
                    Err(e) => {
                        eprintln!("bysyc: {e}");
                        m.notice = Some("crypto engine unavailable — sending disabled".into());
                        true
                    }
                },
                _ => false,
            }
        };
        if repaint {
            self.ctx.request_repaint();
        }
    }

    /// Worker-side of [`MainState::backfill_plaintexts`]: the same retry
    /// pass ([`retry_undecrypted`]) plus the persisted-envelope rebuild
    /// ([`load_file_envelopes`]), run with no state lock held; only the
    /// resulting `file_meta` insertions and the repaint need the world.
    fn backfill(&self, generation: u64, channel_id: i64) {
        let (engine, own_id, known) = {
            let st = guard(&self.state);
            if st.ws_generation != generation {
                return;
            }
            let Some(m) = st.main() else { return };
            (
                m.engine.clone(),
                m.account.id,
                m.file_meta.keys().copied().collect::<HashSet<i64>>(),
            )
        };
        let mut files = load_file_envelopes(&self.store, channel_id, &known);
        let mut changed = !files.is_empty();
        if let Some(engine) = engine {
            let (texts, decrypted_files) =
                retry_undecrypted(&engine, own_id, &self.store, channel_id);
            changed = changed || !texts.is_empty();
            files.extend(decrypted_files);
        }
        if !changed {
            return;
        }
        let repaint = {
            let mut st = guard(&self.state);
            if st.ws_generation != generation {
                return;
            }
            match st.main_mut() {
                Some(m) => {
                    for (id, fe) in files {
                        m.file_meta.insert(id, fe);
                    }
                    true
                }
                None => false,
            }
        };
        if repaint {
            self.ctx.request_repaint();
        }
    }
}
