//! Login / registration view.
//!
//! Submitting flips the phase to `Connecting` and runs the auth call on the
//! tokio runtime; the task persists the token (keychain) + instance URL and
//! username (SQLite settings) and starts the WS gateway on success, or
//! restores the `Disconnected` phase with an error message on failure. The
//! UI thread never blocks.

use std::sync::Arc;

use eframe::egui;

use bysyc_common::protocol::{LoginRequest, RegisterRequest};

use crate::app::BysycApp;
use crate::net::{self, Net};
use crate::state::{Phase, guard};
use crate::store;

/// Local (view-lifetime) input fields.
pub struct LoginView {
    pub server_url: String,
    pub username: String,
    pub password: String,
    pub invite_code: String,
    pub register: bool,
}

impl LoginView {
    pub fn new(default_url: Option<String>) -> Self {
        LoginView {
            server_url: default_url.unwrap_or_else(|| "http://127.0.0.1:8080".into()),
            username: String::new(),
            password: String::new(),
            invite_code: String::new(),
            register: false,
        }
    }
}

pub fn show(app: &mut BysycApp, ui: &mut egui::Ui) {
    let BysycApp {
        state,
        store,
        rt,
        login,
        ..
    } = app;

    egui::CentralPanel::default().show(ui, |ui| {
        let (status, error) = {
            let st = guard(state);
            (
                match &st.phase {
                    Phase::Connecting(s) => Some(s.clone()),
                    _ => None,
                },
                st.login_error.clone(),
            )
        };
        let busy = status.is_some();

        ui.add_space(32.0);
        ui.heading("bysyc");
        ui.weak("self-hosted, end-to-end encrypted chat");
        ui.add_space(16.0);

        ui.horizontal(|ui| {
            ui.selectable_value(&mut login.register, false, "Login");
            ui.selectable_value(&mut login.register, true, "Register");
        });
        ui.add_space(8.0);

        egui::Grid::new("login_grid")
            .num_columns(2)
            .spacing([8.0, 6.0])
            .show(ui, |ui| {
                ui.label("Instance URL");
                ui.add(
                    egui::TextEdit::singleline(&mut login.server_url)
                        .hint_text("http://127.0.0.1:8080"),
                );
                ui.end_row();

                ui.label("Username");
                ui.text_edit_singleline(&mut login.username);
                ui.end_row();

                ui.label("Password");
                ui.add(egui::TextEdit::singleline(&mut login.password).password(true));
                ui.end_row();

                if login.register {
                    ui.label("Invite code");
                    ui.text_edit_singleline(&mut login.invite_code);
                    ui.end_row();
                }
            });

        ui.add_space(12.0);
        let submit_label = if login.register {
            "Create account"
        } else {
            "Sign in"
        };
        let submit = ui
            .add_enabled(!busy, egui::Button::new(submit_label))
            .clicked();

        if let Some(s) = &status {
            ui.add_space(8.0);
            ui.spinner();
            ui.weak(s);
        }
        if let Some(e) = &error {
            ui.add_space(8.0);
            ui.colored_label(egui::Color32::RED, e);
        }

        if submit {
            let base = login.server_url.trim().trim_end_matches('/').to_string();
            let username = login.username.trim().to_string();
            let password = login.password.clone();
            let invite = login.invite_code.trim().to_string();
            let register = login.register;

            let incomplete = base.is_empty()
                || username.is_empty()
                || password.is_empty()
                || (register && invite.is_empty());
            if incomplete {
                guard(state).login_error = Some("fill in every field".into());
            } else {
                {
                    let mut st = guard(state);
                    st.login_error = None;
                    st.phase = Phase::Connecting("Signing in…".into());
                }
                login.password.clear();

                let state = Arc::clone(state);
                let store = Arc::clone(store);
                let rt_in_task = rt.clone();
                let ctx = ui.ctx().clone();
                rt.spawn(async move {
                    let net = Net::new(&base);
                    let result = if register {
                        net.register(&RegisterRequest {
                            username: username.clone(),
                            password: password.clone(),
                            invite_code: invite.clone(),
                            // C2 replaces this with the real identity key.
                            identity_key: net::PLACEHOLDER_IDENTITY_KEY.to_string(),
                        })
                        .await
                    } else {
                        net.login(&LoginRequest {
                            username: username.clone(),
                            password: password.clone(),
                        })
                        .await
                    };
                    match result {
                        Ok(tr) => {
                            {
                                let s = guard(&store);
                                let _ = s.set_setting("server_url", &base);
                                let _ = s.set_setting("username", &tr.account.username);
                            }
                            let _ = store::keyring_set(&tr.account.username, &tr.token);
                            net::spawn_ws(&rt_in_task, state, store, ctx.clone(), base, tr.token);
                        }
                        Err(e) => {
                            let mut st = guard(&state);
                            st.phase = Phase::Disconnected;
                            st.login_error = Some(e);
                        }
                    }
                    ctx.request_repaint();
                });
            }
        }
    });
}
