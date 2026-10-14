//! Voice Calls — owned by C5. Signatures are frozen here so the rest of the
//! client compiles against them; `call::ui` renders from the overlay hook in
//! the main view, and the join/leave/start entry points are called from the
//! channel list and DM header.

pub mod ui;

use std::sync::{Arc, Mutex};

use bysyc_common::protocol::AccountBrief;

use crate::state::ClientState;

/// Join the Call hosted by a guild voice channel (mesh; cap 6).
pub fn join_voice_channel(_state: &Arc<Mutex<ClientState>>, _rt: &tokio::runtime::Handle, _channel_id: i64) {}

/// Leave whatever Call we are currently in (voice channel or private).
pub fn leave_active_call(_state: &Arc<Mutex<ClientState>>, _rt: &tokio::runtime::Handle) {}

/// Start (or answer) a private 1:1 Call with a Friend inside DM channel
/// `dm_channel_id`.
pub fn start_private_call(
    _state: &Arc<Mutex<ClientState>>,
    _rt: &tokio::runtime::Handle,
    _peer: AccountBrief,
    _dm_channel_id: i64,
) {
}
