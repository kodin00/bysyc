//! Voice calls — owned by C5.
//!
//! One [`engine`] session per active call, owned by a dedicated OS thread
//! (str0m is sans-I/O; the thread drives it). This module is the session
//! registry: the frozen entry points create/teardown sessions, and the
//! [`ui`] overlay routes signaling (`state.pending_signals`) and voice
//! rosters into the live session each frame.
//!
//! `call_id` is the voice channel id for channel calls and the DM channel id
//! for private calls, matching what the server fan-outs `CallSignal` on.

pub mod audio;
pub mod engine;
pub mod turn;
pub mod ui;

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

use bysyc_common::protocol::{AccountBrief, CallSignalKind, WsClientBody, WsClientMsg};

use crate::net::{NetHandle, next_msg_id};
use crate::state::ClientState;
use engine::{CallKind, SessionCmd, SessionConfig, SessionHandle};

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

/// A call offer that arrived while no session existed (incoming private
/// call, or a channel peer offering before we joined — the latter is simply
/// ignored since joining creates the session first).
pub struct Incoming {
    pub from: AccountBrief,
    pub call_id: i64,
    pub sdp: String,
    /// When the offer arrived; the overlay auto-declines once the ring
    /// window passes.
    pub arrived: Instant,
}

struct Active {
    handle: SessionHandle,
    /// Roster fingerprint (participant ids) last pushed to the engine.
    roster_fp: Vec<i64>,
}

struct Registry {
    active: Option<Active>,
    incoming: Option<Incoming>,
    /// `ws_generation` when the session started; a change (reconnect,
    /// logout) forces teardown because signaling is gone.
    ws_generation: u64,
}

static REGISTRY: OnceLock<Mutex<Registry>> = OnceLock::new();

fn registry() -> &'static Mutex<Registry> {
    REGISTRY.get_or_init(|| {
        Mutex::new(Registry {
            active: None,
            incoming: None,
            ws_generation: 0,
        })
    })
}

/// Snapshot for the overlay: which call is live and its UiState.
pub struct LiveCall {
    pub call_id: i64,
    pub ui: Arc<engine::UiState>,
}

/// The active session's call id and UI surface, if any.
pub fn live_call() -> Option<LiveCall> {
    let reg = registry().lock().unwrap_or_else(|p| p.into_inner());
    reg.active.as_ref().map(|a| LiveCall {
        call_id: a.handle.ui.call_id,
        ui: a.handle.ui.clone(),
    })
}

/// The pending incoming-call prompt, if any (cloned; cheap).
pub fn incoming_call() -> Option<Incoming> {
    let reg = registry().lock().unwrap_or_else(|p| p.into_inner());
    reg.incoming.as_ref().map(|i| Incoming {
        from: i.from.clone(),
        call_id: i.call_id,
        sdp: i.sdp.clone(),
        arrived: i.arrived,
    })
}

// ---------------------------------------------------------------------------
// Session lifecycle
// ---------------------------------------------------------------------------

fn replace_session(state: &Arc<Mutex<ClientState>>, cfg: SessionConfig, ws_generation: u64) {
    let mut reg = registry().lock().unwrap_or_else(|p| p.into_inner());
    if let Some(old) = reg.active.take() {
        old.handle.send(SessionCmd::Leave);
        // Old engine thread winds down on its own (channel drops below).
    }
    reg.incoming = None;
    let handle = engine::spawn_session(cfg);
    reg.active = Some(Active {
        handle,
        roster_fp: Vec::new(),
    });
    reg.ws_generation = ws_generation;
    let _ = state; // kept for symmetry / future notice pushes
}

fn teardown(state: &Arc<Mutex<ClientState>>, send_voice_leave: bool) {
    let mut reg = registry().lock().unwrap_or_else(|p| p.into_inner());
    if let Some(active) = reg.active.take() {
        active.handle.send(SessionCmd::Leave);
    }
    if let Some(incoming) = reg.incoming.take() {
        // Decline a pending prompt so the caller stops ringing.
        if send_voice_leave
            && let Some(net) = current_net(state)
        {
            let _ = net.out.try_send(WsClientMsg {
                id: next_msg_id(),
                body: WsClientBody::CallSignal {
                    call_id: incoming.call_id,
                    to: incoming.from.id,
                    kind: CallSignalKind::Hangup,
                },
            });
        }
    }
    if send_voice_leave
        && let Some(net) = current_net(state)
    {
        let _ = net.out.try_send(WsClientMsg {
            id: next_msg_id(),
            body: WsClientBody::VoiceLeave,
        });
    }
}

fn current_net(state: &Arc<Mutex<ClientState>>) -> Option<NetHandle> {
    let st = state.lock().unwrap_or_else(|p| p.into_inner());
    if !st.is_logged_in() {
        return None;
    }
    st.main()?.net.clone()
}

// ---------------------------------------------------------------------------
// Frozen entry points
// ---------------------------------------------------------------------------

/// Join the call hosted by a guild voice channel (mesh; cap 6).
pub fn join_voice_channel(
    state: &Arc<Mutex<ClientState>>,
    rt: &tokio::runtime::Handle,
    channel_id: i64,
) {
    let st = state.lock().unwrap_or_else(|p| p.into_inner());
    if !st.is_logged_in() {
        return;
    }
    let Some(main) = st.main() else {
        return;
    };
    let me_id = main.account.id;
    let (audio_in, audio_out) = (main.audio_input_device(), main.audio_output_device());
    let Some(net) = main.net.clone() else {
        return;
    };
    let ws_generation = st.ws_generation;
    drop(st);

    let _ = net.out.try_send(WsClientMsg {
        id: next_msg_id(),
        body: WsClientBody::VoiceJoin { channel_id },
    });

    replace_session(
        state,
        SessionConfig {
            call_id: channel_id,
            kind: CallKind::Channel,
            me_id,
            private_peer: None,
            auto_offer_private: false,
            initial_offer: None,
            input: audio_in,
            output: audio_out,
            net,
            rt: Some(rt.clone()),
        },
        ws_generation,
    );
}

/// Leave whatever call we are currently in (voice channel or private).
pub fn leave_active_call(state: &Arc<Mutex<ClientState>>, _rt: &tokio::runtime::Handle) {
    teardown(state, true);
}

/// Start a private 1:1 call with a friend inside DM channel `dm_channel_id`.
pub fn start_private_call(
    state: &Arc<Mutex<ClientState>>,
    rt: &tokio::runtime::Handle,
    peer: AccountBrief,
    dm_channel_id: i64,
) {
    let st = state.lock().unwrap_or_else(|p| p.into_inner());
    if !st.is_logged_in() {
        return;
    }
    let Some(main) = st.main() else {
        return;
    };
    let me_id = main.account.id;
    let (audio_in, audio_out) = (main.audio_input_device(), main.audio_output_device());
    let Some(net) = main.net.clone() else {
        return;
    };
    let ws_generation = st.ws_generation;
    drop(st);

    replace_session(
        state,
        SessionConfig {
            call_id: dm_channel_id,
            kind: CallKind::Private,
            me_id,
            private_peer: Some(peer),
            // We dial: we offer (the id rule makes this consistent when the
            // peer also clicks; the engine's glare resolution covers the
            // simultaneous case either way).
            auto_offer_private: true,
            initial_offer: None,
            input: audio_in,
            output: audio_out,
            net,
            rt: Some(rt.clone()),
        },
        ws_generation,
    );
}

// ---------------------------------------------------------------------------
// Incoming-call prompt (driven by the overlay)
// ---------------------------------------------------------------------------

/// Accept the pending incoming call (overlay Accept button).
pub fn accept_incoming(state: &Arc<Mutex<ClientState>>, rt: &tokio::runtime::Handle) {
    let st = state.lock().unwrap_or_else(|p| p.into_inner());
    if !st.is_logged_in() {
        return;
    }
    let Some(main) = st.main() else {
        return;
    };
    let me_id = main.account.id;
    let (audio_in, audio_out) = (main.audio_input_device(), main.audio_output_device());
    let Some(net) = main.net.clone() else {
        return;
    };
    let ws_generation = st.ws_generation;
    drop(st);

    let mut reg = registry().lock().unwrap_or_else(|p| p.into_inner());
    let Some(incoming) = reg.incoming.take() else {
        return;
    };
    if reg.active.is_some() {
        // Already in a call; decline instead of two sessions.
        drop(reg);
        let _ = net.out.try_send(WsClientMsg {
            id: next_msg_id(),
            body: WsClientBody::CallSignal {
                call_id: incoming.call_id,
                to: incoming.from.id,
                kind: CallSignalKind::Hangup,
            },
        });
        return;
    }
    drop(reg);

    let Incoming {
        from,
        call_id,
        sdp,
        arrived: _,
    } = incoming;
    let from_id = from.id;
    replace_session(
        state,
        SessionConfig {
            call_id,
            kind: CallKind::Private,
            me_id,
            private_peer: Some(from),
            auto_offer_private: false,
            initial_offer: Some((from_id, sdp)),
            input: audio_in,
            output: audio_out,
            net,
            rt: Some(rt.clone()),
        },
        ws_generation,
    );
}

/// Decline the pending incoming call (overlay Decline button).
pub fn decline_incoming(state: &Arc<Mutex<ClientState>>) {
    let mut reg = registry().lock().unwrap_or_else(|p| p.into_inner());
    let Some(incoming) = reg.incoming.take() else {
        return;
    };
    drop(reg);
    if let Some(net) = current_net(state) {
        let _ = net.out.try_send(WsClientMsg {
            id: next_msg_id(),
            body: WsClientBody::CallSignal {
                call_id: incoming.call_id,
                to: incoming.from.id,
                kind: CallSignalKind::Hangup,
            },
        });
    }
}

// ---------------------------------------------------------------------------
// Overlay plumbing (called from ui::overlay each frame)
// ---------------------------------------------------------------------------

/// Route one drained signal: into the live session if the call matches,
/// into the incoming prompt for a fresh Offer, or nowhere.
pub fn route_signal(
    from: i64,
    call_id: i64,
    kind: CallSignalKind,
    state: &Arc<Mutex<ClientState>>,
) {
    let mut reg = registry().lock().unwrap_or_else(|p| p.into_inner());
    match (&reg.active, &kind) {
        (Some(active), _) if active.handle.ui.call_id == call_id => {
            let handle = active.handle.cmd.clone();
            drop(reg);
            let _ = handle.send(SessionCmd::Signal { from, kind });
            return;
        }
        _ => {}
    }
    // No (or different) live session for this call.
    match kind {
        CallSignalKind::Offer { sdp } => {
            if reg.active.is_none() && reg.incoming.is_none() {
                let from_name = {
                    let st = state.lock().unwrap_or_else(|p| p.into_inner());
                    st.main()
                        .map(|m| m.account_name(from))
                        .unwrap_or_else(|| format!("account {from}"))
                };
                reg.incoming = Some(Incoming {
                    from: AccountBrief {
                        id: from,
                        username: from_name,
                        identity_key: String::new(),
                        online: true,
                    },
                    call_id,
                    sdp,
                    arrived: Instant::now(),
                });
            }
        }
        CallSignalKind::Hangup => {
            // Caller gave up while we were ringing.
            let clears = reg
                .incoming
                .as_ref()
                .is_some_and(|i| i.call_id == call_id && i.from.id == from);
            if clears {
                reg.incoming = None;
            }
        }
        _ => {} // stray Answer/Candidate with no session: ignore
    }
}

/// Push the current channel roster into the session when it changed
/// (VoiceState is a full snapshot, so fingerprinting ids is enough).
pub fn sync_roster(state: &Arc<Mutex<ClientState>>) {
    let st = state.lock().unwrap_or_else(|p| p.into_inner());
    let mut reg = registry().lock().unwrap_or_else(|p| p.into_inner());
    let Some(active) = reg.active.as_mut() else {
        return;
    };
    if active.handle.ui.kind != CallKind::Channel {
        return;
    }
    let call_id = active.handle.ui.call_id;
    let Some(participants) = st.main().and_then(|m| m.voice.get(&call_id)) else {
        return;
    };
    let fp: Vec<i64> = participants.iter().map(|a| a.id).collect();
    if fp == active.roster_fp {
        return;
    }
    active.roster_fp = fp;
    let handle = active.handle.cmd.clone();
    drop(reg);
    let _ = handle.send(SessionCmd::Roster(participants.clone()));
}

/// Tear the session down when the connection it was born on is gone.
pub fn teardown_if_disconnected(state: &Arc<Mutex<ClientState>>) {
    let st = state.lock().unwrap_or_else(|p| p.into_inner());
    let logged_in = st.is_logged_in();
    let generation = st.ws_generation;
    drop(st);
    if !logged_in {
        teardown(state, false);
        return;
    }
    let reg = registry().lock().unwrap_or_else(|p| p.into_inner());
    let stale = reg.active.is_some() && reg.ws_generation != generation;
    drop(reg);
    if stale {
        teardown(state, false);
    }
}

/// Tear the session down when the engine reports the call finished on its
/// own (peer hangup, ICE death, no-answer timeout, engine crash). Without
/// this the overlay would keep rendering live Mute/Leave buttons — or a
/// "connecting…" window — over a session whose thread is already gone.
pub fn teardown_if_finished(state: &Arc<Mutex<ClientState>>) {
    let finished = {
        let reg = registry().lock().unwrap_or_else(|p| p.into_inner());
        reg.active
            .as_ref()
            .is_some_and(|a| a.handle.ui.finished.load(Ordering::Relaxed))
    };
    if finished {
        teardown(state, true);
    }
}
