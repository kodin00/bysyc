//! Call overlay UI — owned by C5.
//!
//! Rendered every frame after the main view: drains `pending_signals` into
//! the live session (or the incoming-call prompt), pushes voice rosters to
//! the engine, and draws the call chrome (participants, mute, leave) plus
//! the incoming-call prompt. All call state lives in the engine thread's
//! [`UiState`](crate::call::engine::UiState); this side only reads it.

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use eframe::egui;

use super::{
    accept_incoming, decline_incoming, incoming_call, leave_active_call, live_call, sync_roster,
    teardown_if_disconnected, teardown_if_finished,
};
use crate::state::ClientState;

/// How long the incoming-call prompt rings before auto-declining (the
/// caller's side gives up with "no answer" at the same duration).
const RING_TIMEOUT: Duration = Duration::from_secs(30);

/// Rendered every frame after the main view.
pub fn overlay(ctx: &egui::Context, state: &Arc<Mutex<ClientState>>, rt: &tokio::runtime::Handle) {
    // 1. Connection-level teardown (logout / reconnect kills signaling).
    teardown_if_disconnected(state);

    // 2. Engine-reported end (peer hangup, ICE death, no answer): drop the
    //    registry entry so the chrome disappears with the session.
    teardown_if_finished(state);

    // 3. Drain relayed call signals.
    let signals = {
        let mut st = state.lock().unwrap_or_else(|p| p.into_inner());
        st.main_mut()
            .map(|m| std::mem::take(&mut m.pending_signals))
            .unwrap_or_default()
    };
    for (from, call_id, kind) in signals {
        super::route_signal(from, call_id, kind, state);
    }

    // 4. Voice roster → engine (channel calls).
    sync_roster(state);

    // 5. Chrome.
    let live = live_call();
    let mut incoming = incoming_call();
    if live.is_some() || incoming.is_some() {
        // Call state changes on the engine thread at 20 ms cadence.
        ctx.request_repaint_after(Duration::from_millis(100));
    }
    // Ring out: a prompt older than the window declines itself so the
    // caller stops ringing.
    if incoming
        .as_ref()
        .is_some_and(|i| i.arrived.elapsed() > RING_TIMEOUT)
    {
        decline_incoming(state);
        incoming = None;
    }
    // Keyboard: Escape declines a ringing prompt, or — with no prompt up
    // and no text field holding focus, so typing in chat can never drop
    // the call — leaves the live call.
    if ctx.input(|i| i.key_pressed(egui::Key::Escape)) {
        if incoming.is_some() {
            decline_incoming(state);
            incoming = None;
        } else if live.is_some() && ctx.memory(|m| m.focused().is_none()) {
            leave_active_call(state, rt);
        }
    }
    if let Some(live) = &live {
        call_window(ctx, state, rt, live.call_id, &live.ui);
    }
    if let Some(incoming) = &incoming {
        incoming_window(ctx, state, rt, incoming.from.username.as_str());
    }
}

fn call_window(
    ctx: &egui::Context,
    state: &Arc<Mutex<ClientState>>,
    rt: &tokio::runtime::Handle,
    call_id: i64,
    ui_state: &Arc<crate::call::engine::UiState>,
) {
    let title = {
        let st = state.lock().unwrap_or_else(|p| p.into_inner());
        st.main()
            .map(|m| m.channel_name(call_id))
            .unwrap_or_else(|| format!("call {call_id}"))
    };
    egui::Window::new(format!("In call — {title}"))
        .anchor(egui::Align2::RIGHT_BOTTOM, [-8.0, -8.0])
        .collapsible(false)
        .resizable(false)
        .show(ctx, |ui| {
            let participants = ui_state
                .participants
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .clone();

            if participants.is_empty() {
                ui.weak("waiting for participants…");
            } else {
                egui::Grid::new("call_participants")
                    .num_columns(1)
                    .show(ui, |ui| {
                        for p in &participants {
                            let dot = if p.speaking {
                                "●"
                            } else if p.connected {
                                "·"
                            } else {
                                " "
                            };
                            let row = format!("{dot} {}", p.name);
                            if p.connected {
                                ui.strong(row);
                            } else {
                                ui.weak(row);
                            }
                            ui.end_row();
                        }
                    });
            }

            ui.add_space(6.0);
            ui.horizontal(|ui| {
                let muted = ui_state.muted.load(Ordering::Relaxed);
                let label = if muted { "Unmute" } else { "Mute" };
                if ui.button(label).clicked() {
                    ui_state.muted.store(!muted, Ordering::Relaxed);
                }
                if ui.button("Leave").clicked() {
                    leave_active_call(state, rt);
                }
            });

            let status = ui_state
                .status
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .clone();
            if !status.is_empty() {
                ui.weak(status);
            }
            let rtt = ui_state.rtt_ms.load(Ordering::Relaxed);
            if rtt > 0 {
                ui.weak(format!("latency: {rtt}ms"));
            }
            if let Some(err) = ui_state
                .audio_error
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .clone()
            {
                ui.colored_label(egui::Color32::from_rgb(220, 100, 100), err);
            }
        });
}

fn incoming_window(
    ctx: &egui::Context,
    state: &Arc<Mutex<ClientState>>,
    rt: &tokio::runtime::Handle,
    from: &str,
) {
    egui::Window::new("Incoming call")
        .anchor(egui::Align2::RIGHT_TOP, [-8.0, 8.0])
        .collapsible(false)
        .resizable(false)
        .show(ctx, |ui| {
            ui.label(format!("Incoming call from {from}"));
            ui.horizontal(|ui| {
                if ui.button("Accept").clicked() {
                    accept_incoming(state, rt);
                }
                if ui.button("Decline").clicked() {
                    decline_incoming(state);
                }
            });
            ui.weak("esc to decline");
        });
}
