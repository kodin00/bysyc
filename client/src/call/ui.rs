//! Call overlay UI — owned by C5.

use std::sync::{Arc, Mutex};

use eframe::egui;

use crate::state::ClientState;

/// Rendered every frame after the main view: active-call chrome, participant
/// tiles, and the drain loop for `pending_signals` / `voice` state.
pub fn overlay(_ctx: &egui::Context, _state: &Arc<Mutex<ClientState>>, _rt: &tokio::runtime::Handle) {}
