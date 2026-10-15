//! The logged-in main view: three columns.
//!
//! - left: guilds, then Friends, then DMs (with unread badges and presence
//!   dots), plus log out.
//! - middle: channels of the selected guild (voice channels list their call
//!   participant count; joining is C5's), or the friends panel (accept /
//!   decline requests, open DMs, add by username).
//! - right: message history of the selected channel or DM plus the composer.
//!
//! History is loaded from SQLite first, then merged with a REST page on
//! first open; sends are optimistic (negative temp ids, pinned at the tail)
//! and reconciled when the REST response lands. Typing events are throttled
//! to one per 3 s and pruned after [`TYPING_TTL_SECS`].

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use eframe::egui;

use bysyc_common::protocol::{
    ChannelKind, CreateChannelRequest, CreateGuildInviteRequest, CreateGuildRequest,
    JoinGuildRequest, MessageDto, MessageKind, OpenDmRequest, WsClientBody, WsClientMsg,
};

use crate::app::BysycApp;
use crate::crypto::Envelope;
use crate::net::{self, NetHandle};
use crate::state::{ClientState, ConnStatus, Selection, TYPING_TTL_SECS, guard, now_ms};
use crate::store::Store;
use crate::views::attachments;

/// View-lifetime UI state (input buffers, throttles).
pub struct MainView {
    /// Composer text per channel id.
    pub composer: HashMap<i64, String>,
    /// Last time we sent a Typing event per channel (3 s throttle).
    pub last_typing_sent: HashMap<i64, Instant>,
    /// Source of negative optimistic message ids.
    pub temp_id: i64,
    /// Add-friend input.
    pub add_friend: String,
    /// Per channel: the message id the composer is replying to.
    pub reply_to: HashMap<i64, i64>,
    /// "+"-guild popup open?
    pub guild_popup: bool,
    /// Inputs for the guild popup (create / join-by-code).
    pub new_guild_name: String,
    pub join_code: String,
    /// "+ channel" popup open (guild owner only).
    pub channel_popup: bool,
    pub new_channel_name: String,
    /// `false` = text channel, `true` = voice channel.
    pub new_channel_voice: bool,
    /// "+ dm" friend picker open?
    pub dm_picker: bool,
    /// Decoded-and-downscaled attachment images by attachment id. UI-thread
    /// only (textures cannot be created elsewhere); never persisted.
    pub image_cache: HashMap<i64, egui::TextureHandle>,
    /// Worker threads hand finished image decodes to the UI thread here.
    pub image_tx: std::sync::mpsc::Sender<attachments::DecodedImage>,
    pub image_rx: std::sync::mpsc::Receiver<attachments::DecodedImage>,
    /// Open image lightbox: (attachment id, name).
    pub image_popup: Option<(i64, String)>,
}

impl MainView {
    pub fn new() -> Self {
        let (image_tx, image_rx) = std::sync::mpsc::channel();
        MainView {
            composer: HashMap::new(),
            last_typing_sent: HashMap::new(),
            temp_id: -1,
            add_friend: String::new(),
            reply_to: HashMap::new(),
            guild_popup: false,
            new_guild_name: String::new(),
            join_code: String::new(),
            channel_popup: false,
            new_channel_name: String::new(),
            new_channel_voice: false,
            dm_picker: false,
            image_cache: HashMap::new(),
            image_tx,
            image_rx,
            image_popup: None,
        }
    }
}

pub fn show(app: &mut BysycApp, ui: &mut egui::Ui) {
    let BysycApp {
        state,
        store,
        rt,
        login: _,
        main_view,
        net_task: _,
    } = app;
    let ctx = ui.ctx().clone();

    // egui 0.36: one `Panel` type with side constructors. Both side columns
    // are drag-resizable within a bounded range so they stay usable from
    // small windows (min) up to wide ones (max).
    egui::Panel::left("nav")
        .resizable(true)
        .default_size(190.0)
        .min_size(140.0)
        .max_size(400.0)
        .show(ui, |ui| nav(ui, state, store, rt, main_view, &ctx));

    egui::Panel::left("middle")
        .resizable(true)
        .default_size(210.0)
        .min_size(140.0)
        .max_size(400.0)
        .show(ui, |ui| middle(ui, state, rt, main_view, &ctx));

    egui::CentralPanel::default().show(ui, |ui| chat(ui, state, store, rt, main_view, &ctx));

    // Transient popups driven by background tasks (invite codes).
    invite_window(state, &ctx);

    // C5 renders the call overlay from here.
    crate::call::ui::overlay(&ctx, state, rt);
}

// ---------------------------------------------------------------------------
// Left column: guilds / friends / DMs
// ---------------------------------------------------------------------------

fn nav(
    ui: &mut egui::Ui,
    state: &Arc<Mutex<ClientState>>,
    store: &Arc<Mutex<Store>>,
    rt: &tokio::runtime::Handle,
    mv: &mut MainView,
    ctx: &egui::Context,
) {
    let (guilds, dms, selected, unread, online, incoming) = {
        let st = guard(state);
        let Some(m) = st.main() else { return };
        (
            m.guilds.clone(),
            m.dms.clone(),
            m.selected,
            m.unread.clone(),
            m.online.clone(),
            m.incoming_requests.len(),
        )
    };

    ui.heading("bysyc");
    ui.add_space(6.0);

    // The guild/friends/DM list scrolls when it outgrows the column; the
    // heading above and the Log out button below stay pinned.
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            for g in &guilds {
                let is_current =
                    matches!(selected, Selection::Channel(c) if g.channels.iter().any(|ch| ch.id == c));
                let marker = if is_current { "> " } else { "" };
                if ui
                    .selectable_label(is_current, format!("{marker}{}", g.name))
                    .clicked()
                {
                    let mut st = guard(state);
                    if let Some(m) = st.main_mut() {
                        if let Some(ch) = m.first_text_channel(g.id) {
                            m.selected = Selection::Channel(ch);
                            m.unread.remove(&ch);
                        }
                    }
                }
            }
            if ui.button("+ guild").clicked() {
                mv.guild_popup = !mv.guild_popup;
            }

            ui.add_space(8.0);
            ui.separator();

            let friends_label = if incoming > 0 {
                format!("Friends ({incoming})")
            } else {
                "Friends".to_string()
            };
            if ui
                .selectable_label(matches!(selected, Selection::Friends), friends_label)
                .clicked()
            {
                if let Some(m) = guard(state).main_mut() {
                    m.selected = Selection::Friends;
                }
            }

            ui.add_space(4.0);
            for dm in &dms {
                let sel = matches!(selected, Selection::Dm(c) if c == dm.channel.id);
                ui.horizontal(|ui| {
                    let on = online.contains(&dm.peer.id);
                    ui.colored_label(
                        if on {
                            egui::Color32::LIGHT_GREEN
                        } else {
                            egui::Color32::GRAY
                        },
                        "●",
                    );
                    if ui.selectable_label(sel, dm.peer.username.clone()).clicked() {
                        let mut st = guard(state);
                        if let Some(m) = st.main_mut() {
                            m.selected = Selection::Dm(dm.channel.id);
                            m.unread.remove(&dm.channel.id);
                        }
                    }
                    if unread.contains(&dm.channel.id) {
                        ui.colored_label(egui::Color32::RED, "•");
                    }
                });
            }
            if ui.button("+ dm").clicked() {
                mv.dm_picker = !mv.dm_picker;
            }
        });

    ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
        if ui.button("Log out").clicked() {
            logout(state, store, rt);
        }
    });

    guild_popup(state, rt, mv, ctx);
    dm_picker(state, rt, mv, ctx);
}

/// Create-a-guild / join-by-code window ("+ guild").
fn guild_popup(
    state: &Arc<Mutex<ClientState>>,
    rt: &tokio::runtime::Handle,
    mv: &mut MainView,
    ctx: &egui::Context,
) {
    let mut open = mv.guild_popup;
    let mut close = false;
    egui::Window::new("Add a guild")
        .id(egui::Id::new("guild_popup"))
        .open(&mut open)
        .collapsible(false)
        .show(ctx, |ui| {
            ui.label("Create");
            ui.text_edit_singleline(&mut mv.new_guild_name);
            if ui.button("Create guild").clicked() {
                let name = mv.new_guild_name.trim().to_string();
                if !name.is_empty() {
                    mv.new_guild_name.clear();
                    close = true;
                    spawn_guild_rest(state, rt, ctx, move |h| async move {
                        h.net.create_guild(&CreateGuildRequest { name }).await
                    });
                }
            }
            ui.separator();
            ui.label("Join with an invite code");
            ui.text_edit_singleline(&mut mv.join_code);
            if ui.button("Join").clicked() {
                let code = mv.join_code.trim().to_string();
                if !code.is_empty() {
                    mv.join_code.clear();
                    close = true;
                    spawn_guild_rest(state, rt, ctx, move |h| async move {
                        h.net.join_guild(&JoinGuildRequest { code }).await
                    });
                }
            }
        });
    mv.guild_popup = open && !close;
}

/// Shared REST half of create/join guild: run the call, merge the returned
/// guild locally (the WS `GuildJoined` echo is deduped on insert).
fn spawn_guild_rest<F, Fut>(
    state: &Arc<Mutex<ClientState>>,
    rt: &tokio::runtime::Handle,
    ctx: &egui::Context,
    fut_fn: F,
) where
    F: FnOnce(NetHandle) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Result<bysyc_common::protocol::GuildInfo, String>>
        + Send
        + 'static,
{
    let Some(h) = net_handle(state) else { return };
    let state = Arc::clone(state);
    let ctx = ctx.clone();
    rt.spawn(async move {
        let h2 = h.clone();
        match fut_fn(h).await {
            Ok(g) => {
                // Joined guild channels: subscribe now instead of waiting
                // out the periodic heartbeat (see NetHandle::heartbeat).
                h2.heartbeat();
                let mut st = guard(&state);
                if let Some(m) = st.main_mut() {
                    if !m.guilds.iter().any(|x| x.id == g.id) {
                        m.guilds.push(g);
                    }
                }
            }
            Err(e) => {
                if let Some(m) = guard(&state).main_mut() {
                    m.notice = Some(e);
                }
            }
        }
        ctx.request_repaint();
    });
}

fn logout(state: &Arc<Mutex<ClientState>>, store: &Arc<Mutex<Store>>, rt: &tokio::runtime::Handle) {
    let taken = {
        let st = guard(state);
        st.main()
            .map(|m| (m.account.username.clone(), m.net.clone()))
    };
    let (username, handle) = taken.unwrap_or_else(|| (String::new(), None));

    // Generation bump makes the WS loop stop reconnecting.
    guard(state).sign_out_local("Signed out.");

    if !username.is_empty() {
        crate::store::token_delete(&username);
        let s = guard(store);
        let _ = s.del_setting("username");
    }
    if let Some(h) = handle {
        rt.spawn(async move {
            let _ = h.net.logout().await;
        });
    }
}

/// "+ dm" picker: friends list → open (or reuse) a DM and select it.
fn dm_picker(
    state: &Arc<Mutex<ClientState>>,
    rt: &tokio::runtime::Handle,
    mv: &mut MainView,
    ctx: &egui::Context,
) {
    let friends = {
        let st = guard(state);
        st.main().map(|m| m.friends.clone()).unwrap_or_default()
    };
    let mut open = mv.dm_picker;
    let mut close = false;
    egui::Window::new("Start a direct message")
        .id(egui::Id::new("dm_picker"))
        .open(&mut open)
        .collapsible(false)
        .show(ctx, |ui| {
            if friends.is_empty() {
                ui.weak("no friends yet — add some on the Friends page");
            }
            for f in &friends {
                if ui.button(f.username.clone()).clicked() {
                    close = true;
                    open_dm_and_select(state, rt, ctx, f.id);
                }
            }
        });
    mv.dm_picker = open && !close;
}

/// Open (or reuse) a DM with `peer_id` and select it.
fn open_dm_and_select(
    state: &Arc<Mutex<ClientState>>,
    rt: &tokio::runtime::Handle,
    ctx: &egui::Context,
    peer_id: i64,
) {
    let Some(h) = net_handle(state) else { return };
    let state = Arc::clone(state);
    let ctx = ctx.clone();
    rt.spawn(async move {
        match h
            .net
            .open_dm(&OpenDmRequest {
                account_id: peer_id,
            })
            .await
        {
            Ok(dm) => {
                // New channel: poke the gateway to subscribe us now (see
                // NetHandle::heartbeat) instead of waiting out the periodic
                // heartbeat interval.
                h.heartbeat();
                let channel_id = dm.channel.id;
                let mut st = guard(&state);
                if let Some(m) = st.main_mut() {
                    if !m.dms.iter().any(|d| d.channel.id == channel_id) {
                        m.dms.push(dm);
                    }
                    m.selected = Selection::Dm(channel_id);
                }
            }
            Err(e) => {
                if let Some(m) = guard(&state).main_mut() {
                    m.notice = Some(e);
                }
            }
        }
        ctx.request_repaint();
    });
}

/// Owner's "invite": mint a 24 h code and surface it in [`invite_window`].
fn spawn_invite(
    state: &Arc<Mutex<ClientState>>,
    rt: &tokio::runtime::Handle,
    ctx: &egui::Context,
    guild_id: i64,
    guild_name: String,
) {
    let Some(h) = net_handle(state) else { return };
    let state = Arc::clone(state);
    let ctx = ctx.clone();
    rt.spawn(async move {
        match h
            .net
            .create_guild_invite(
                guild_id,
                &CreateGuildInviteRequest {
                    max_uses: None,
                    ttl_secs: Some(24 * 60 * 60),
                },
            )
            .await
        {
            Ok(inv) => {
                if let Some(m) = guard(&state).main_mut() {
                    m.invite = Some((guild_name, inv.code));
                }
            }
            Err(e) => {
                if let Some(m) = guard(&state).main_mut() {
                    m.notice = Some(e);
                }
            }
        }
        ctx.request_repaint();
    });
}

/// Invite-code window: filled by the owner's "invite" action, with a
/// copy-to-clipboard button.
fn invite_window(state: &Arc<Mutex<ClientState>>, ctx: &egui::Context) {
    let invite = { guard(state).main().and_then(|m| m.invite.clone()) };
    let Some((guild, code)) = invite else { return };
    egui::Window::new("Guild invite")
        .id(egui::Id::new("invite_window"))
        .collapsible(false)
        .show(ctx, |ui| {
            ui.label(format!("Invite to {guild}:"));
            ui.monospace(code.clone());
            if ui.button("Copy").clicked() {
                ui.ctx().output_mut(|o| {
                    o.commands.push(egui::OutputCommand::CopyText(code.clone()));
                });
            }
            if ui.button("Close").clicked() {
                if let Some(m) = guard(state).main_mut() {
                    m.invite = None;
                }
            }
        });
}

// ---------------------------------------------------------------------------
// Middle column: channels of the guild, DM info, or friends panel
// ---------------------------------------------------------------------------

fn middle(
    ui: &mut egui::Ui,
    state: &Arc<Mutex<ClientState>>,
    rt: &tokio::runtime::Handle,
    mv: &mut MainView,
    ctx: &egui::Context,
) {
    let (selected, guilds, voice, my_id) = {
        let st = guard(state);
        let Some(m) = st.main() else { return };
        (m.selected, m.guilds.clone(), m.voice.clone(), m.account.id)
    };

    // Channels / friends scroll so a long list never pushes the layout.
    egui::ScrollArea::vertical()
        .auto_shrink([false, true])
        .show(ui, |ui| match selected {
            Selection::Friends => friends_panel(ui, state, rt, mv, ctx),
            Selection::Dm(ch) => {
                let peer = {
                    let st = guard(state);
                    st.main().and_then(|m| {
                        m.dms
                            .iter()
                            .find(|d| d.channel.id == ch)
                            .map(|d| d.peer.clone())
                    })
                };
                let Some(peer) = peer else { return };
                ui.heading(format!("@{}", peer.username));
                ui.weak("private, end-to-end encrypted");
                if ui.button("Call").clicked() {
                    crate::call::start_private_call(state, rt, peer, ch);
                }
            }
            Selection::Channel(ch) => {
                let Some(g) = guilds
                    .iter()
                    .find(|g| g.channels.iter().any(|c| c.id == ch))
                else {
                    ui.weak("nothing selected");
                    return;
                };
                ui.heading(g.name.clone());
                let is_owner = g.owner_id == my_id;
                if is_owner {
                    ui.horizontal(|ui| {
                        if ui.small_button("+ channel").clicked() {
                            mv.channel_popup = !mv.channel_popup;
                        }
                        if ui.small_button("invite").clicked() {
                            spawn_invite(state, rt, ctx, g.id, g.name.clone());
                        }
                    });
                }
                ui.separator();
                for c in &g.channels {
                    match c.kind {
                        ChannelKind::Text => {
                            let sel = c.id == ch;
                            ui.horizontal(|ui| {
                                if ui.selectable_label(sel, format!("# {}", c.name)).clicked() {
                                    let mut st = guard(state);
                                    if let Some(m) = st.main_mut() {
                                        m.selected = Selection::Channel(c.id);
                                        m.unread.remove(&c.id);
                                    }
                                }
                                if is_owner && ui.small_button("×").clicked() {
                                    let id = c.id;
                                    spawn_rest(state, rt, ctx, move |h| async move {
                                        h.net.delete_channel(id).await
                                    });
                                }
                            });
                        }
                        ChannelKind::Voice => {
                            let participants = voice.get(&c.id);
                            let n = participants.map_or(0, Vec::len);
                            let joined =
                                participants.is_some_and(|v| v.iter().any(|p| p.id == my_id));
                            let label = if joined {
                                format!("(v) {} — {n} in call  [leave]", c.name)
                            } else {
                                format!("(v) {} — {n} in call", c.name)
                            };
                            ui.horizontal(|ui| {
                                if ui.selectable_label(joined, label).clicked() {
                                    if joined {
                                        crate::call::leave_active_call(state, rt);
                                    } else {
                                        crate::call::join_voice_channel(state, rt, c.id);
                                    }
                                }
                                if is_owner && ui.small_button("×").clicked() {
                                    let id = c.id;
                                    spawn_rest(state, rt, ctx, move |h| async move {
                                        h.net.delete_channel(id).await
                                    });
                                }
                            });
                        }
                        ChannelKind::Dm => {}
                    }
                }
                channel_popup(state, rt, mv, ctx, g.id, is_owner);
            }
        });
}

/// "+ channel" window for guild owners: name + text/voice toggle.
fn channel_popup(
    state: &Arc<Mutex<ClientState>>,
    rt: &tokio::runtime::Handle,
    mv: &mut MainView,
    ctx: &egui::Context,
    guild_id: i64,
    is_owner: bool,
) {
    if !is_owner {
        return;
    }
    let mut open = mv.channel_popup;
    let mut close = false;
    egui::Window::new("New channel")
        .id(egui::Id::new("channel_popup"))
        .open(&mut open)
        .collapsible(false)
        .show(ctx, |ui| {
            ui.text_edit_singleline(&mut mv.new_channel_name);
            ui.checkbox(&mut mv.new_channel_voice, "voice channel");
            if ui.button("Create").clicked() {
                let name = mv.new_channel_name.trim().to_string();
                if !name.is_empty() {
                    mv.new_channel_name.clear();
                    close = true;
                    let kind = if mv.new_channel_voice {
                        ChannelKind::Voice
                    } else {
                        ChannelKind::Text
                    };
                    spawn_channel_rest(state, rt, ctx, guild_id, name, kind);
                }
            }
        });
    mv.channel_popup = open && !close;
}

fn spawn_channel_rest(
    state: &Arc<Mutex<ClientState>>,
    rt: &tokio::runtime::Handle,
    ctx: &egui::Context,
    guild_id: i64,
    name: String,
    kind: ChannelKind,
) {
    let Some(h) = net_handle(state) else { return };
    let state = Arc::clone(state);
    let ctx = ctx.clone();
    rt.spawn(async move {
        match h
            .net
            .create_channel(guild_id, &CreateChannelRequest { name, kind })
            .await
        {
            Ok(c) => {
                let mut st = guard(&state);
                if let Some(m) = st.main_mut() {
                    if let Some(g) = m.guilds.iter_mut().find(|g| g.id == guild_id) {
                        if !g.channels.iter().any(|x| x.id == c.id) {
                            g.channels.push(c);
                        }
                    }
                }
            }
            Err(e) => {
                if let Some(m) = guard(&state).main_mut() {
                    m.notice = Some(e);
                }
            }
        }
        ctx.request_repaint();
    });
}

fn friends_panel(
    ui: &mut egui::Ui,
    state: &Arc<Mutex<ClientState>>,
    rt: &tokio::runtime::Handle,
    mv: &mut MainView,
    ctx: &egui::Context,
) {
    let (friends, incoming, outgoing, online) = {
        let st = guard(state);
        let Some(m) = st.main() else { return };
        (
            m.friends.clone(),
            m.incoming_requests.clone(),
            m.outgoing_requests.clone(),
            m.online.clone(),
        )
    };

    ui.heading("Friends");
    ui.separator();

    if !incoming.is_empty() {
        ui.strong("Incoming requests");
        for f in &incoming {
            ui.horizontal(|ui| {
                ui.colored_label(
                    if online.contains(&f.id) {
                        egui::Color32::LIGHT_GREEN
                    } else {
                        egui::Color32::GRAY
                    },
                    "●",
                );
                ui.label(f.username.clone());
                if ui.button("Accept").clicked() {
                    let (id, brief) = (f.id, f.clone());
                    {
                        let mut st = guard(state);
                        if let Some(m) = st.main_mut() {
                            m.incoming_requests.retain(|a| a.id != id);
                            if !m.friends.iter().any(|a| a.id == id) {
                                m.friends.push(brief);
                            }
                        }
                    }
                    spawn_rest(state, rt, ctx, move |h| async move {
                        h.net.accept_friend_request(id).await
                    });
                }
                if ui.button("Decline").clicked() {
                    let id = f.id;
                    {
                        let mut st = guard(state);
                        if let Some(m) = st.main_mut() {
                            m.incoming_requests.retain(|a| a.id != id);
                        }
                    }
                    spawn_rest(state, rt, ctx, move |h| async move {
                        h.net.decline_friend_request(id).await
                    });
                }
            });
        }
        ui.add_space(4.0);
    }

    if !outgoing.is_empty() {
        ui.strong("Sent requests");
        for f in &outgoing {
            ui.horizontal(|ui| {
                ui.label(f.username.clone());
                if ui.small_button("cancel").clicked() {
                    let id = f.id;
                    {
                        let mut st = guard(state);
                        if let Some(m) = st.main_mut() {
                            m.outgoing_requests.retain(|a| a.id != id);
                        }
                    }
                    // The decline endpoint doubles as cancel for the
                    // caller's own outgoing request.
                    spawn_rest(state, rt, ctx, move |h| async move {
                        h.net.decline_friend_request(id).await
                    });
                }
            });
        }
        ui.add_space(4.0);
    }

    ui.strong("Friends");
    if friends.is_empty() {
        ui.weak("none yet — add someone below");
    }
    for f in &friends {
        ui.horizontal(|ui| {
            let on = online.contains(&f.id);
            ui.colored_label(
                if on {
                    egui::Color32::LIGHT_GREEN
                } else {
                    egui::Color32::GRAY
                },
                "●",
            );
            ui.label(f.username.clone());
            if ui.button("Message").clicked() {
                open_dm_and_select(state, rt, ctx, f.id);
            }
        });
    }

    ui.add_space(8.0);
    ui.separator();
    ui.label("Add friend");
    let field = ui.add(
        egui::TextEdit::singleline(&mut mv.add_friend)
            .hint_text("username")
            .desired_width(130.0),
    );
    let enter = field.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
    if enter || ui.button("Send request").clicked() {
        let name = mv.add_friend.trim().to_string();
        if !name.is_empty() {
            mv.add_friend.clear();
            let state2 = Arc::clone(state);
            let ctx2 = ctx.clone();
            if let Some(h) = net_handle(state) {
                rt.spawn(async move {
                    // The protocol sends friend requests by account id, so
                    // resolve the username first.
                    match h.net.lookup_username(&name).await {
                        Ok(brief) => match h.net.send_friend_request(brief.id).await {
                            Ok(()) => {
                                let mut st = guard(&state2);
                                if let Some(m) = st.main_mut() {
                                    if !m.outgoing_requests.iter().any(|a| a.id == brief.id) {
                                        m.outgoing_requests.push(brief);
                                    }
                                }
                            }
                            Err(e) => {
                                if let Some(m) = guard(&state2).main_mut() {
                                    m.notice = Some(e);
                                }
                            }
                        },
                        Err(e) => {
                            if let Some(m) = guard(&state2).main_mut() {
                                m.notice = Some(e);
                            }
                        }
                    }
                    ctx2.request_repaint();
                });
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Right column: chat
// ---------------------------------------------------------------------------

fn chat(
    ui: &mut egui::Ui,
    state: &Arc<Mutex<ClientState>>,
    store: &Arc<Mutex<Store>>,
    rt: &tokio::runtime::Handle,
    mv: &mut MainView,
    ctx: &egui::Context,
) {
    // Bring finished background image decodes onto the UI thread as
    // textures (no-op when nothing is pending).
    attachments::drain_decoded(ctx, mv);

    // Status / notice banners.
    let (reconnecting, notice) = {
        let st = guard(state);
        match st.main() {
            Some(m) => {
                let r = match &m.connection {
                    ConnStatus::Reconnecting(reason) => Some(reason.clone()),
                    ConnStatus::Online => None,
                };
                (r, m.notice.clone())
            }
            None => (None, None),
        }
    };
    if let Some(reason) = reconnecting {
        ui.colored_label(egui::Color32::YELLOW, format!("offline — {reason}"));
    }
    if let Some(n) = notice {
        ui.horizontal(|ui| {
            ui.colored_label(egui::Color32::RED, n);
            if ui.small_button("x").clicked() {
                if let Some(m) = guard(state).main_mut() {
                    m.notice = None;
                }
            }
        });
    }

    let Some(ch) = guard(state).main().and_then(|m| m.selected_channel()) else {
        ui.heading("bysyc");
        ui.weak("select a channel, a direct message, or Friends");
        return;
    };

    let title = guard(state)
        .main()
        .map(|m| m.channel_name(ch))
        .unwrap_or_default();
    ui.heading(title);

    // First open: seed from SQLite, then fetch the newest REST page.
    let newly_loaded = {
        let mut st = guard(state);
        st.main_mut().map(|m| m.loaded.insert(ch)).unwrap_or(false)
    };
    if newly_loaded {
        fetch_history(state, store, rt, ctx, ch, None);
    }
    if let Some(m) = guard(state).main_mut() {
        m.unread.remove(&ch);
    }

    // Older history.
    let has_more = guard(state)
        .main()
        .and_then(|m| m.has_more.get(&ch).copied())
        .unwrap_or(true);
    if has_more && ui.button("Load older").clicked() {
        let oldest = guard(state).main().and_then(|m| {
            m.messages
                .get(&ch)
                .and_then(|v| v.iter().find(|x| x.id > 0).map(|x| x.id))
        });
        match oldest {
            Some(before) => fetch_history(state, store, rt, ctx, ch, Some(before)),
            None => {
                if let Some(m) = guard(state).main_mut() {
                    m.has_more.insert(ch, false);
                }
            }
        }
    }

    // Composer strip, carved out as a bottom panel BEFORE the history
    // ScrollArea: a vertical ScrollArea claims all remaining height of its
    // parent, so widgets laid out after it were pushed off-screen (the
    // invisible-composer bug). Typing indicator, reply banner, and upload
    // progress strip live here too, directly above the input.
    egui::Panel::bottom("chat_composer")
        .resizable(false)
        .min_size(52.0)
        .show(ui, |ui| {
            // Typing indicator (pruned past its TTL).
            let typing_line: Option<String> = {
                let mut st = guard(state);
                if let Some(m) = st.main_mut() {
                    match m.typing.get(&ch).copied() {
                        Some((sender, at)) if at.elapsed().as_secs() < TYPING_TTL_SECS => {
                            Some(m.account_name(sender))
                        }
                        Some(_) => {
                            m.typing.remove(&ch);
                            None
                        }
                        None => None,
                    }
                } else {
                    None
                }
            };
            if let Some(name) = typing_line {
                ui.weak(format!("{name} is typing…"));
            }

            // Reply banner: who and what is being replied to, cancellable.
            if let Some(rid) = mv.reply_to.get(&ch).copied() {
                let target = {
                    let st = guard(state);
                    st.main().and_then(|m| {
                        m.messages.get(&ch).and_then(|v| {
                            v.iter()
                                .find(|x| x.id == rid)
                                .map(|x| (m.account_name(x.sender_id), preview_body(store, x)))
                        })
                    })
                };
                let known = target.is_some();
                let (name, snippet) = target.unwrap_or_else(|| ("(gone)".into(), String::new()));
                if known {
                    ui.horizontal(|ui| {
                        ui.weak(format!("replying to {name}: {snippet}"));
                        if ui.small_button("cancel").clicked() {
                            mv.reply_to.remove(&ch);
                        }
                    });
                } else {
                    mv.reply_to.remove(&ch);
                }
            }

            // Attachment upload progress strip (above the composer).
            attachments::uploads_ui(ui, state);

            // Composer.
            let response = {
                let buf = mv.composer.entry(ch).or_default();
                ui.add(
                    egui::TextEdit::singleline(buf)
                        .hint_text("Message…  (Ctrl+Enter to send)")
                        .desired_width(f32::INFINITY),
                )
            };
            if response.changed() {
                maybe_send_typing(state, mv, ch);
            }
            let mut send = false;
            ui.horizontal(|ui| {
                if ui.button("Send").clicked() {
                    send = true;
                }
                if ui.button("+ attach").clicked() {
                    attachments::begin_attach(state, store, rt, ctx, mv, ch);
                }
            });
            if response.lost_focus()
                && ui.input(|i| i.key_pressed(egui::Key::Enter) && i.modifiers.ctrl)
            {
                send = true;
            }
            if send {
                let text = mv.composer.get(&ch).cloned().unwrap_or_default();
                let text = text.trim().to_string();
                if !text.is_empty() {
                    mv.composer.insert(ch, String::new());
                    do_send(state, store, rt, ctx, mv, ch, text);
                }
            }
        });

    // Message list — virtualized per ADR 0003.
    let count = guard(state)
        .main()
        .and_then(|m| m.messages.get(&ch))
        .map_or(0, Vec::len);
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .stick_to_bottom(true)
        .show_rows(ui, 18.0, count, |ui, range| {
            // Snapshot the visible slice under the state lock, then read
            // plaintexts from the store after releasing it (lock order
            // state → store only, never held the other way around).
            let rows: Vec<(MessageDto, String)> = {
                let st = guard(state);
                let Some(m) = st.main() else { return };
                let Some(msgs) = m.messages.get(&ch) else {
                    return;
                };
                range
                    .filter_map(|i| {
                        let msg = msgs.get(i)?;
                        if msg.kind == MessageKind::Control {
                            return None;
                        }
                        Some((msg.clone(), m.account_name(msg.sender_id)))
                    })
                    .collect()
            };
            let plains: HashMap<i64, String> = {
                let s = guard(store);
                rows.iter()
                    .filter(|(msg, _)| msg.id > 0)
                    .filter_map(|(msg, _)| s.plaintext(msg.id).map(|p| (msg.id, p)))
                    .collect()
            };
            // Reply prefixes need the replied-to sender's name.
            let reply_names: HashMap<i64, String> = {
                let st = guard(state);
                let Some(m) = st.main() else {
                    return;
                };
                match m.messages.get(&ch) {
                    Some(msgs) => rows
                        .iter()
                        .filter_map(|(msg, _)| msg.reply_to)
                        .filter_map(|rid| {
                            msgs.iter()
                                .find(|x| x.id == rid)
                                .map(|x| (rid, m.account_name(x.sender_id)))
                        })
                        .collect(),
                    None => HashMap::new(),
                }
            };
            // File envelopes for the visible attachment rows, keyed by
            // message id (stashed at decrypt time in `file_meta`).
            let file_envs: HashMap<i64, Envelope> = {
                let st = guard(state);
                match st.main() {
                    Some(m) => rows
                        .iter()
                        .filter(|(msg, _)| msg.attachment.is_some())
                        .filter_map(|(msg, _)| {
                            m.file_meta.get(&msg.id).cloned().map(|fe| (msg.id, fe))
                        })
                        .collect(),
                    None => HashMap::new(),
                }
            };
            for (msg, sender) in &rows {
                let time = fmt_time(msg.created_at_ms);
                let prefix = msg
                    .reply_to
                    .and_then(|rid| reply_names.get(&rid))
                    .map(|n| format!("↪ [{n}] "))
                    .unwrap_or_default();
                let header = format!("{time}  {sender}:  {prefix}");
                // Attachment rows render from the stashed File envelope;
                // everything else is the plain text line.
                if let (Some(att), Some(fe)) = (msg.attachment.as_ref(), file_envs.get(&msg.id)) {
                    ui.label(header);
                    attachments::attachment_row(ui, state, rt, ctx, mv, att, fe);
                    if msg.id > 0 && ui.small_button("reply").clicked() {
                        mv.reply_to.insert(ch, msg.id);
                    }
                } else {
                    let body = if msg.id < 0 {
                        format!("{} …", msg.content)
                    } else {
                        plains
                            .get(&msg.id)
                            .cloned()
                            .unwrap_or_else(|| "[encrypted]".into())
                    };
                    ui.horizontal(|ui| {
                        ui.label(format!("{header}{body}"));
                        if msg.id > 0 && ui.small_button("reply").clicked() {
                            mv.reply_to.insert(ch, msg.id);
                        }
                    });
                }
            }
        });

    // Image lightbox for clicked thumbnails.
    attachments::image_popup(state, rt, ctx, mv);
}

/// Fetch a page of history into the cache + store. `before == None` fetches
/// the newest page (seeding from the local cache first).
fn fetch_history(
    state: &Arc<Mutex<ClientState>>,
    store: &Arc<Mutex<Store>>,
    rt: &tokio::runtime::Handle,
    ctx: &egui::Context,
    ch: i64,
    before: Option<i64>,
) {
    let Some(h) = net_handle(state) else { return };

    if before.is_none() {
        let local = guard(store).messages_for(ch, None, 200);
        if !local.is_empty() {
            let mut st = guard(state);
            if let Some(m) = st.main_mut() {
                m.merge_messages(ch, local);
            }
        }
    }

    let state = Arc::clone(state);
    let store = Arc::clone(store);
    let ctx = ctx.clone();
    rt.spawn(async move {
        match h.net.channel_messages(ch, before, 50).await {
            Ok(page) => {
                {
                    let s = guard(&store);
                    for m in &page.messages {
                        let _ = s.append_message(m);
                    }
                }
                {
                    let mut st = guard(&state);
                    if let Some(m) = st.main_mut() {
                        m.merge_messages(ch, page.messages);
                        m.has_more.insert(ch, page.has_more);
                    }
                }
                // Rows that arrived before their Megolm session share get a
                // second chance now that this page is cached.
                {
                    let mut st = guard(&state);
                    if let Some(m) = st.main_mut() {
                        m.backfill_plaintexts(&store, ch);
                    }
                }
            }
            Err(e) => {
                if let Some(m) = guard(&state).main_mut() {
                    m.notice = Some(e);
                }
            }
        }
        ctx.request_repaint();
    });
}

/// The encrypted send path for chat text. Everything the crypto half needs
/// is gathered under one state lock up front; the network work then runs on
/// the runtime.
///
/// The encrypt → share-first → POST sequence itself lives in
/// [`attachments::encrypt_share_and_send`], shared with the attachment
/// send path (C4): Megolm-encrypt the [`Envelope::Chat`], and when this is
/// the channel's first send, a rotation, or an unknown sid after restart,
/// mailbox every roster peer the session key *before* the message POST so
/// the very first message is already decryptable. On success the plaintext
/// is stored for our own row (the engine deliberately holds no
/// self-import) and the optimistic temp row is reconciled.
///
/// No engine → no send: chat refuses to fall back to plaintext.
#[allow(clippy::too_many_arguments)]
fn do_send(
    state: &Arc<Mutex<ClientState>>,
    store: &Arc<Mutex<Store>>,
    rt: &tokio::runtime::Handle,
    ctx: &egui::Context,
    mv: &mut MainView,
    ch: i64,
    text: String,
) {
    let temp = mv.temp_id;
    mv.temp_id -= 1;
    let reply_to = mv.reply_to.remove(&ch);

    let gather = {
        let st = guard(state);
        st.main().map(|m| (m.account.id, m.engine.clone()))
    };
    let Some((me, engine)) = gather else {
        return;
    };
    let Some(engine) = engine else {
        if let Some(m) = guard(state).main_mut() {
            m.notice = Some("crypto engine unavailable — sending is disabled".into());
        }
        return;
    };

    let optimistic = MessageDto {
        id: temp,
        channel_id: ch,
        sender_id: me,
        kind: MessageKind::Chat,
        content: text.clone(),
        reply_to,
        attachment: None,
        created_at_ms: now_ms(),
    };
    if let Some(m) = guard(state).main_mut() {
        m.messages.entry(ch).or_default().push(optimistic);
    }

    let Some(h) = net_handle(state) else {
        if let Some(m) = guard(state).main_mut() {
            if let Some(v) = m.messages.get_mut(&ch) {
                v.retain(|x| x.id != temp);
            }
            m.notice = Some("not connected".into());
        }
        return;
    };

    let state = Arc::clone(state);
    let store = Arc::clone(store);
    let ctx = ctx.clone();
    rt.spawn(async move {
        let envelope = Envelope::Chat {
            text: text.clone(),
            reply_to,
        };
        if let Err(e) = attachments::encrypt_share_and_send(
            &state, &store, &h.net, &engine, ch, &envelope, temp, None,
        )
        .await
        {
            let mut st = guard(&state);
            if let Some(m) = st.main_mut() {
                if let Some(v) = m.messages.get_mut(&ch) {
                    v.retain(|x| x.id != temp);
                }
                m.notice = Some(format!("send failed: {e}"));
            }
        }
        ctx.request_repaint();
    });
}

/// Short quote of a message for the reply banner: decrypted plaintext when
/// we have it, else the raw buffer (temps), else a placeholder.
fn preview_body(store: &Arc<Mutex<Store>>, msg: &MessageDto) -> String {
    let body = if msg.id < 0 {
        msg.content.clone()
    } else {
        guard(store)
            .plaintext(msg.id)
            .unwrap_or_else(|| "[encrypted]".into())
    };
    let mut s: String = body.chars().take(40).collect();
    if body.chars().count() > 40 {
        s.push('…');
    }
    s
}

/// One Typing event per channel per 3 s while the composer changes.
fn maybe_send_typing(state: &Arc<Mutex<ClientState>>, mv: &mut MainView, ch: i64) {
    let now = Instant::now();
    let due = match mv.last_typing_sent.get(&ch) {
        Some(t) => now.duration_since(*t) >= Duration::from_secs(3),
        None => true,
    };
    if due {
        mv.last_typing_sent.insert(ch, now);
        if let Some(h) = net_handle(state) {
            let _ = h.out.try_send(WsClientMsg {
                id: net::next_msg_id(),
                body: WsClientBody::Typing { channel_id: ch },
            });
        }
    }
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

/// Current net handle, or `None` while disconnected. Shared with the
/// attachments view (C4).
pub(crate) fn net_handle(state: &Arc<Mutex<ClientState>>) -> Option<NetHandle> {
    guard(state).main().and_then(|m| m.net.clone())
}

/// Run a REST call on the runtime, surfacing failures as a notice.
fn spawn_rest<F, Fut>(
    state: &Arc<Mutex<ClientState>>,
    rt: &tokio::runtime::Handle,
    ctx: &egui::Context,
    fut_fn: F,
) where
    F: FnOnce(NetHandle) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Result<(), String>> + Send + 'static,
{
    let Some(h) = net_handle(state) else { return };
    let state = Arc::clone(state);
    let ctx = ctx.clone();
    rt.spawn(async move {
        if let Err(e) = fut_fn(h).await {
            if let Some(m) = guard(&state).main_mut() {
                m.notice = Some(e);
            }
        }
        ctx.request_repaint();
    });
}

/// UTC hh:mm (local timezones are C3 polish).
fn fmt_time(ms: i64) -> String {
    let secs = ms.div_euclid(1000).rem_euclid(86_400);
    format!("{:02}:{:02}", secs / 3600, (secs % 3600) / 60)
}
