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
        // predates Unicode 11); also the basis of the composer's emoji
        // picker (see [`crate::views::emoji`]).
        crate::views::emoji::install_fonts(&cc.egui_ctx);

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
