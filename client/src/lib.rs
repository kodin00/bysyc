//! Library target: the whole client stack (state, net, store, crypto,
//! views) so integration tests (`tests/e2e.rs`) can drive the real client
//! headlessly against a live Instance. The binary is a thin shell over
//! these modules.

pub mod app;
pub mod call;
pub mod crypto;
pub mod net;
pub mod state;
pub mod store;
pub mod views;
