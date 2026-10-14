//! Shared wire types between the bysyc client and server.
//!
//! Everything that crosses the network boundary lives here so the two
//! crates cannot drift on the protocol.

/// Current wire protocol version. Clients and server refuse mismatched versions.
pub const PROTOCOL_VERSION: u32 = 1;
