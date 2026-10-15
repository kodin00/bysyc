//! bysyc client entry point: one tokio runtime for all background work, the
//! local SQLite store, shared client state, and the eframe window.

use std::sync::{Arc, Mutex};

use eframe::egui;

use bysyc_client::app::BysycApp;
use bysyc_client::state::ClientState;
use bysyc_client::store::Store;

/// Rasterize the decaying-gear icon from `assets/icon.svg` for the window.
///
/// Note: on macOS, winit cannot set window icons at runtime (the dock icon
/// comes from the .app bundle), so this only takes effect on Windows/Linux.
fn load_icon() -> Option<egui::IconData> {
    let svg = include_bytes!("../../assets/icon.svg");
    // Rasterize well above the 64-unit viewBox so taskbar/alt-tab sizes stay
    // crisp; `SizeHint::Width` keeps the square aspect ratio.
    let image = egui_extras::image::load_svg_bytes_with_size(
        svg,
        egui::SizeHint::Width(256),
        &Default::default(), // resvg usvg options (resvg is not a direct dependency)
    )
    .ok()?;
    let rgba = image
        .pixels
        .iter()
        .flat_map(|p| p.to_array())
        .collect::<Vec<u8>>();
    Some(egui::IconData {
        rgba,
        width: image.size[0] as u32,
        height: image.size[1] as u32,
    })
}

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

    let viewport = egui::ViewportBuilder::default()
        // The app opens on the login form: start compact (either tab
        // fits without scrolling) and let the user resize or maximize.
        .with_inner_size([480.0, 560.0])
        // Floor for the three-column layout + composer: below this the
        // side columns (each ≥ 140 px) starve the chat area.
        .with_min_inner_size([480.0, 360.0])
        .with_title("bysyc");
    let options = eframe::NativeOptions {
        // See `load_icon` for the macOS caveat (icon applies on Windows/Linux).
        viewport: match load_icon() {
            Some(icon) => viewport.with_icon(icon),
            None => viewport,
        },
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
