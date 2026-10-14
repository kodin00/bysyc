//! Voice channel participants + signaling relay. Owned by S5 — these stubs
//! fix the signatures the gateway (S4) codes against.

pub fn router() -> axum::Router<crate::db::AppState> {
    axum::Router::new()
}

use crate::db::AppState;
use crate::error::ApiResult;
use bysyc_common::protocol::{AccountBrief, CallSignalKind};

/// Join a voice channel: enforce the 6-participant cap, record membership,
/// publish the new VoiceState snapshot to the channel, return participants.
pub async fn join(
    _state: &AppState,
    _channel_id: i64,
    _account_id: i64,
) -> ApiResult<Vec<AccountBrief>> {
    unimplemented!("S5 implements voice::join")
}

/// Leave a voice channel and publish the updated VoiceState snapshot.
pub async fn leave(_state: &AppState, _channel_id: i64, _account_id: i64) -> ApiResult<()> {
    unimplemented!("S5 implements voice::leave")
}

/// Relay one WebRTC signal from `from` to `to` within `call_id`.
pub async fn relay_signal(
    _state: &AppState,
    _call_id: i64,
    _from: i64,
    _to: i64,
    _kind: CallSignalKind,
) -> ApiResult<()> {
    unimplemented!("S5 implements voice::relay_signal")
}
