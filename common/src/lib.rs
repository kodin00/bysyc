//! Shared wire types between the bysyc client and server.
//!
//! Everything that crosses the network boundary lives here so the two
//! crates cannot drift on the protocol. See [`protocol`] for the full
//! contract.

/// Current wire protocol version. Clients and server refuse mismatched versions.
pub const PROTOCOL_VERSION: u32 = 1;

/// The wire protocol: every REST DTO, the WebSocket envelopes, and the
/// error model shared by client and server.
pub mod protocol;

pub use protocol::*;
