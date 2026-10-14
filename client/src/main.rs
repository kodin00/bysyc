//! bysyc client entry point: one tokio runtime for all background work, the
//! local SQLite store, shared client state, and the eframe window.

mod app;
mod call;
mod crypto;
mod net;
mod state;
mod store;
mod views;

use std::sync::{Arc, Mutex};

use eframe::egui;

use app::BysycApp;
use state::ClientState;
use store::Store;

fn main() -> eframe::Result<()> {
    // Single runtime owned for the whole process lifetime: the UI thread
    // only renders; every network task runs here. Dropped after
    // `run_native` returns (it blocks until the window closes).
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("bysyc: start tokio runtime");
    let handle = rt.handle().clone();

    let store = Arc::new(Mutex::new(
        Store::open_default().expect("bysyc: open local database"),
    ));
    let client_state = Arc::new(Mutex::new(ClientState::new()));

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1100.0, 720.0])
            .with_title("bysyc"),
        ..Default::default()
    };
    let result = eframe::run_native(
        "bysyc",
        options,
        Box::new(|cc| Ok(Box::new(BysycApp::new(cc, client_state, store, handle)))),
    );
    drop(rt);
    result
}
