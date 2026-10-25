//! Settings modal: audio output/input device pickers.
//!
//! [`settings_window`] is rendered per frame while its `open` toggle is set
//! (a gear button in the nav panel owns that toggle). Device choices persist
//! to the local store and are read by the call engine when it next opens its
//! cpal streams, so a change applies to the next call.

use std::sync::{Arc, Mutex};

use eframe::egui;

use crate::state::{ClientState, guard};
use crate::store::Store;

/// Modal settings window. `open` is the caller's toggle (a gear button in
/// the nav panel); ESC or the window's close button clears it. Audio device
/// choices persist to the local store and take effect on the next call.
pub fn settings_window(
    ctx: &egui::Context,
    state: &Arc<Mutex<ClientState>>,
    store: &Arc<Mutex<Store>>,
    rt: &tokio::runtime::Handle,
    open: &mut bool,
) {
    let mut esc = false;
    egui::Window::new("Settings")
        .open(open)
        .default_size([360.0, 280.0])
        .resizable(true)
        .show(ctx, |ui| {
            if ui.input_mut(|i| i.consume_key(egui::Modifiers::NONE, egui::Key::Escape)) {
                esc = true;
            }
            ui.heading("Audio");
            ui.add_space(4.0);

            // ---- Output device ----
            let current_out = guard(state).main().and_then(|m| m.audio_output_device());
            let out_devices = crate::call::audio::output_devices();
            ui.horizontal(|ui| {
                ui.label("Output:");
                let selected = current_out.as_deref().unwrap_or("System default");
                egui::ComboBox::from_label("output_device")
                    .selected_text(selected)
                    .show_ui(ui, |ui| {
                        if ui
                            .selectable_label(current_out.is_none(), "System default")
                            .clicked()
                        {
                            apply_output(state, store, None);
                        }
                        for (name, _) in &out_devices {
                            if ui
                                .selectable_label(
                                    current_out.as_deref() == Some(name.as_str()),
                                    name,
                                )
                                .clicked()
                            {
                                apply_output(state, store, Some(name.clone()));
                            }
                        }
                    });
            });

            // ---- Input device ----
            let current_in = guard(state).main().and_then(|m| m.audio_input_device());
            let in_devices = crate::call::audio::input_devices();
            ui.horizontal(|ui| {
                ui.label("Input:");
                let selected = current_in.as_deref().unwrap_or("System default");
                egui::ComboBox::from_label("input_device")
                    .selected_text(selected)
                    .show_ui(ui, |ui| {
                        if ui
                            .selectable_label(current_in.is_none(), "System default")
                            .clicked()
                        {
                            apply_input(state, store, None);
                        }
                        for (name, _) in &in_devices {
                            if ui
                                .selectable_label(
                                    current_in.as_deref() == Some(name.as_str()),
                                    name,
                                )
                                .clicked()
                            {
                                apply_input(state, store, Some(name.clone()));
                            }
                        }
                    });
            });

            ui.add_space(8.0);
            ui.weak("Changes apply to the next call.");

            // ---- Invites (admin only) ----
            let is_admin = guard(state).main().is_some_and(|m| m.account.is_admin);
            if is_admin {
                ui.add_space(10.0);
                ui.heading("Invites");
                ui.add_space(4.0);
                ui.label("Mint a single-use code a friend can register with.");
                let code = guard(state).main().and_then(|m| m.reg_invite.clone());
                if let Some(code) = code.as_deref() {
                    ui.horizontal(|ui| {
                        ui.monospace(code);
                        if ui.button("Copy").clicked() {
                            ui.ctx().output_mut(|o| {
                                o.commands
                                    .push(egui::OutputCommand::CopyText(code.to_string()));
                            });
                        }
                    });
                }
                if ui.button("Create invite").clicked()
                    && let Some(h) = crate::views::main_view::net_handle(state)
                {
                    let s = Arc::clone(state);
                    let c = ctx.clone();
                    rt.spawn(async move {
                        match h.net.create_invite().await {
                            Ok(code) => {
                                if let Some(m) = guard(&s).main_mut() {
                                    m.reg_invite = Some(code);
                                }
                            }
                            Err(e) => {
                                if let Some(m) = guard(&s).main_mut() {
                                    m.notice = Some(e);
                                }
                            }
                        }
                        c.request_repaint();
                    });
                }
            }
        });
    if esc {
        *open = false;
    }
}

fn apply_output(state: &Arc<Mutex<ClientState>>, store: &Arc<Mutex<Store>>, name: Option<String>) {
    if let Some(m) = guard(state).main_mut() {
        m.audio_output = name.clone();
    }
    let _ = guard(store).set_audio_output(name.as_deref());
}

fn apply_input(state: &Arc<Mutex<ClientState>>, store: &Arc<Mutex<Store>>, name: Option<String>) {
    if let Some(m) = guard(state).main_mut() {
        m.audio_input = name.clone();
    }
    let _ = guard(store).set_audio_input(name.as_deref());
}
