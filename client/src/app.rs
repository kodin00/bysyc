//! eframe shell: owns the shared state, the store, the tokio handle, and
//! the view-lifetime widgets; delegates rendering to [`crate::views`] based
//! on the current phase.

use std::sync::{Arc, Mutex};

use eframe::egui;

use crate::state::{self, ClientState, Phase};
use crate::store::Store;
use crate::views::login::LoginView;
use crate::views::main_view::MainView;

pub struct BysycApp {
    pub state: Arc<Mutex<ClientState>>,
    pub store: Arc<Mutex<Store>>,
    pub rt: tokio::runtime::Handle,
    pub login: LoginView,
    pub main_view: MainView,
    /// Latest background net task. WS tasks stop themselves when the
    /// state's `ws_generation` moves, so this is bookkeeping, not a
    /// lifecycle handle.
    pub net_task: Option<tokio::task::JoinHandle<()>>,
}

impl BysycApp {
    pub fn new(
        cc: &eframe::CreationContext<'_>,
        state: Arc<Mutex<ClientState>>,
        store: Arc<Mutex<Store>>,
        rt: tokio::runtime::Handle,
    ) -> Self {
        // Image loaders for the embedded SVG icons in the chat view (paper
        // plane / paper clip). Idempotent, so a re-created app is fine.
        egui_extras::install_image_loaders(&cc.egui_ctx);

        // Current Noto Emoji as the emoji fallback font (the builtin copy
        // predates Unicode 11) — incoming messages and IME-typed emoji
        // render through it.
        install_fonts(&cc.egui_ctx);

        let default_url = {
            let s = state::guard(&store);
            s.setting("server_url")
        };
        let mut app = BysycApp {
            login: LoginView::new(default_url),
            state,
            store,
            rt,
            main_view: MainView::new(),
            net_task: None,
        };
        app.try_restore_session(cc.egui_ctx.clone());
        app
    }

    /// Stored instance URL + username + saved token: validate via
    /// `GET /auth/me` and open the WS gateway on success; otherwise clear
    /// the saved token and fall through to the login view.
    fn try_restore_session(&mut self, ctx: egui::Context) {
        let base = {
            let s = state::guard(&self.store);
            s.setting("server_url")
        };
        let username = {
            let s = state::guard(&self.store);
            s.setting("username")
        };
        let (Some(base), Some(username)) = (base, username) else {
            return;
        };
        let Some(token) = crate::store::token_get(&username) else {
            return;
        };

        {
            let mut st = state::guard(&self.state);
            st.phase = Phase::Connecting("Restoring session…".into());
            st.login_error = None;
        }

        let state = Arc::clone(&self.state);
        let store = Arc::clone(&self.store);
        let rt = self.rt.clone();
        self.net_task = Some(self.rt.spawn(async move {
            let net = crate::net::Net::authenticated(&base, &token);
            match net.me().await {
                Ok(me) => {
                    // The engine must exist before the first WS Ready lands
                    // (the mailbox batch it carries holds our session shares).
                    // A failed bootstrap is unrecoverable for E2EE — better a
                    // clean login screen than a session that can only eavesdrop.
                    match crate::store::bootstrap_engine(&store, &me.username) {
                        Ok((engine, outbound)) => {
                            {
                                let mut st = state::guard(&state);
                                st.pending_engine = Some(state::EngineBoot {
                                    engine: engine.clone(),
                                    outbound,
                                });
                            }
                            // Session restore re-publishes keys too: the
                            // instance may have been reset, and topped-up
                            // OTKs keep prekey messages flowing.
                            let pk_net = crate::net::Net::authenticated(&base, &token);
                            let pk_engine = engine.clone();
                            tokio::spawn(async move {
                                crate::net::publish_keys(&pk_net, &pk_engine).await;
                            });
                            crate::net::spawn_ws(&rt, state, store, ctx.clone(), base, token);
                        }
                        Err(e) => {
                            eprintln!("bysyc: {e}");
                            crate::store::token_delete(&username);
                            {
                                let s = state::guard(&store);
                                let _ = s.del_setting("username");
                            }
                            let mut st = state::guard(&state);
                            st.sign_out_local("");
                            st.login_error =
                                Some("cannot open the local crypto store — sign in again".into());
                        }
                    }
                }
                Err(_) => {
                    crate::store::token_delete(&username);
                    {
                        let s = state::guard(&store);
                        let _ = s.del_setting("username");
                    }
                    let mut st = state::guard(&state);
                    st.sign_out_local("");
                    st.login_error = None;
                }
            }
            ctx.request_repaint();
        }));
    }
}

impl eframe::App for BysycApp {
    /// Nothing to poll: background tasks call `ctx.request_repaint()` when
    /// state changes, and the UI recomputes transient displays (typing
    /// indicators, banners) while rendering.
    fn logic(&mut self, _ctx: &egui::Context, _frame: &mut eframe::Frame) {}

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let logged_in = state::guard(&self.state).is_logged_in();
        if logged_in {
            crate::views::main_view::show(self, ui);
        } else {
            crate::views::login::show(self, ui);
        }
    }
}

/// Current Noto Emoji (monochrome outline), embedded at compile time.
/// Variable font; epaint renders the default (Regular) instance.
const NOTO_EMOJI: &[u8] = include_bytes!("../assets/fonts/NotoEmoji-Regular.ttf");

/// Replace epaint's bundled 2019 `NotoEmoji-Regular` (already a fallback in
/// both default families) with the current one from [`NOTO_EMOJI`]. Called
/// once at app creation; `Context::set_fonts` rebuilds the font atlas, so
/// re-created apps are fine too.
///
/// egui/epaint 0.36 rasterize fonts with skrifa and draw flat-color glyph
/// outlines only — bitmap color-emoji formats (Apple Color Emoji sbix, CBDT,
/// COLR) have no path, so anything outside the registered font set renders
/// as tofu. The bundled copy predates Unicode 11 (even 🙂 is missing);
/// replacing it lets incoming messages and IME-typed emoji render as
/// theme-tinted monochrome outlines. The font lives in `client/assets/fonts/`
/// under the SIL OFL 1.1 (`OFL.txt` beside it).
fn install_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    // Same slot and scale tweak (emoji glyphs run tall) as the builtin, so
    // both the Proportional and Monospace fallback lists pick it up without
    // further edits.
    fonts.font_data.insert(
        "NotoEmoji-Regular".to_owned(),
        std::sync::Arc::new(egui::FontData::from_static(NOTO_EMOJI).tweak(
            egui::FontTweak {
                scale: 0.81, // Make smaller — matches the builtin entry
                ..Default::default()
            },
        )),
    );
    ctx.set_fonts(fonts);
}

/// The embedded font must be a loadable sfnt (TrueType/OTF): a truncated or
/// HTML "download" would otherwise fail only at first emoji render.
#[test]
fn font_blob_is_sfnt() {
    assert!(!NOTO_EMOJI.is_empty());
    let magic: [u8; 4] = NOTO_EMOJI[..4].try_into().unwrap();
    assert!(
        magic == [0x00, 0x01, 0x00, 0x00] || magic == *b"OTTO" || magic == *b"true",
        "unexpected sfnt magic: {magic:?}"
    );
}

/// The replacement must register and parse through the real epaint font
/// pipeline (an unparsable font panics at first use). 🙂 is Unicode 9-era
/// and 🥲 is Unicode 13 — the builtin 2019 copy has neither, so this also
/// proves the upgrade actually took.
///
/// `Fonts::has_glyphs` cannot verify this: epaint's replacement sentinel
/// is '◻' (U+25FB), which NotoEmoji itself covers (the builtin copy too),
/// so every glyph the emoji font owns compares equal to the replacement
/// face and reports false — even on stock egui. Instead: shaping 🙂 and 🥲
/// must produce two glyphs with distinct atlas rectangles (tofu would
/// reuse the one replacement rectangle), and the live
/// "NotoEmoji-Regular" must be the shipped variable font (the 2019
/// builtin is static, so it reports no variation axes).
#[test]
fn installed_font_covers_modern_emoji() {
    let ctx = egui::Context::default();
    install_fonts(&ctx);
    // Fonts build lazily at the first pass begin (pixels_per_point is
    // unknown before then); building panics on any unparsable face, so
    // getting past this point proves our blob loaded.
    ctx.begin_pass(egui::RawInput::default());
    let galley = ctx.fonts_mut(|f| {
        f.layout(
            "🙂🥲".to_owned(),
            egui::FontId::proportional(14.0),
            egui::Color32::WHITE,
            100.0,
        )
    });
    // Rasterizing glyphs queues an atlas texture delta; drop it cleanly
    // (dropping it unapplied trips a debug assert in epaint).
    ctx.end_pass().textures_delta.clear();

    let uvs: Vec<_> = galley
        .rows
        .iter()
        .flat_map(|row| row.row.glyphs.iter().map(|g| g.uv_rect))
        .collect();
    assert_eq!(uvs.len(), 2, "expected one glyph per emoji");
    assert_ne!(
        uvs[0], uvs[1],
        "🙂 and 🥲 both resolved to the same (replacement) glyph"
    );

    let axes = ctx.fonts(|f| {
        f.definitions().font_data["NotoEmoji-Regular"].variation_axes()
    });
    assert!(
        !axes.is_empty(),
        "live NotoEmoji-Regular is static — the shipped variable font was not installed"
    );
}
