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
    ChannelKind, MessageDto, MessageKind, OpenDmRequest, SendMessageRequest, WsClientBody,
    WsClientMsg,
};

use crate::app::BysycApp;
use crate::net::{self, NetHandle};
use crate::state::{ClientState, ConnStatus, Selection, TYPING_TTL_SECS, guard, now_ms};
use crate::store::Store;

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
}

impl MainView {
    pub fn new() -> Self {
        MainView {
            composer: HashMap::new(),
            last_typing_sent: HashMap::new(),
            temp_id: -1,
            add_friend: String::new(),
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

    // egui 0.36: one `Panel` type with side constructors.
    egui::Panel::left("nav")
        .resizable(false)
        .default_size(190.0)
        .show(ui, |ui| nav(ui, state, store, rt, &ctx));

    egui::Panel::left("middle")
        .resizable(false)
        .default_size(210.0)
        .show(ui, |ui| middle(ui, state, rt, main_view, &ctx));

    egui::CentralPanel::default().show(ui, |ui| chat(ui, state, store, rt, main_view, &ctx));

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
    _ctx: &egui::Context,
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

    ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
        if ui.button("Log out").clicked() {
            logout(state, store, rt);
        }
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
        crate::store::keyring_delete(&username);
        let s = guard(store);
        let _ = s.del_setting("username");
    }
    if let Some(h) = handle {
        rt.spawn(async move {
            let _ = h.net.logout().await;
        });
    }
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

    match selected {
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
            ui.separator();
            for c in &g.channels {
                match c.kind {
                    ChannelKind::Text => {
                        let sel = c.id == ch;
                        if ui.selectable_label(sel, format!("# {}", c.name)).clicked() {
                            let mut st = guard(state);
                            if let Some(m) = st.main_mut() {
                                m.selected = Selection::Channel(c.id);
                                m.unread.remove(&c.id);
                            }
                        }
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
                        if ui.selectable_label(joined, label).clicked() {
                            if joined {
                                crate::call::leave_active_call(state, rt);
                            } else {
                                crate::call::join_voice_channel(state, rt, c.id);
                            }
                        }
                    }
                    ChannelKind::Dm => {}
                }
            }
        }
    }
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
            ui.label(f.username.clone());
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
                let peer_id = f.id;
                let state2 = Arc::clone(state);
                let ctx2 = ctx.clone();
                if let Some(h) = net_handle(state) {
                    rt.spawn(async move {
                        match h
                            .net
                            .open_dm(&OpenDmRequest {
                                account_id: peer_id,
                            })
                            .await
                        {
                            Ok(dm) => {
                                let channel_id = dm.channel.id;
                                let mut st = guard(&state2);
                                if let Some(m) = st.main_mut() {
                                    if !m.dms.iter().any(|d| d.channel.id == channel_id) {
                                        m.dms.push(dm);
                                    }
                                    m.selected = Selection::Dm(channel_id);
                                }
                            }
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

    // Message list — virtualized per ADR 0003.
    let count = guard(state)
        .main()
        .and_then(|m| m.messages.get(&ch))
        .map_or(0, Vec::len);
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .stick_to_bottom(true)
        .show_rows(ui, 18.0, count, |ui, range| {
            let st = guard(state);
            let Some(m) = st.main() else { return };
            let Some(msgs) = m.messages.get(&ch) else {
                return;
            };
            for i in range {
                let Some(msg) = msgs.get(i) else { continue };
                let time = fmt_time(msg.created_at_ms);
                let sender = m.account_name(msg.sender_id);
                // C2/C3 replace this with the decrypted plaintext.
                let body = if msg.id < 0 {
                    msg.content.clone() + " …"
                } else {
                    "[encrypted]".to_string()
                };
                ui.label(format!("{time}  {sender}:  {body}"));
            }
        });

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
    let mut send = ui.button("Send").clicked();
    if response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter) && i.modifiers.ctrl) {
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
                let mut st = guard(&state);
                if let Some(m) = st.main_mut() {
                    m.merge_messages(ch, page.messages);
                    m.has_more.insert(ch, page.has_more);
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
    let me = guard(state).main().map(|m| m.account.id).unwrap_or(0);
    let optimistic = MessageDto {
        id: temp,
        channel_id: ch,
        sender_id: me,
        kind: MessageKind::Chat,
        content: text.clone(),
        reply_to: None,
        attachment: None,
        created_at_ms: now_ms(),
    };
    if let Some(m) = guard(state).main_mut() {
        m.messages.entry(ch).or_default().push(optimistic);
    }

    let Some(h) = net_handle(state) else {
        if let Some(m) = guard(state).main_mut() {
            m.notice = Some("not connected".into());
        }
        return;
    };

    let state = Arc::clone(state);
    let store = Arc::clone(store);
    let ctx = ctx.clone();
    rt.spawn(async move {
        let req = SendMessageRequest {
            kind: MessageKind::Chat,
            content: text,
            reply_to: None,
            attachment_id: None,
        };
        match net::send_message(&h.net, ch, &req).await {
            Ok(dto) => {
                {
                    let s = guard(&store);
                    let _ = s.append_message(&dto);
                }
                let mut st = guard(&state);
                if let Some(m) = st.main_mut() {
                    m.replace_temp(temp, dto);
                }
            }
            Err(e) => {
                let mut st = guard(&state);
                if let Some(m) = st.main_mut() {
                    if let Some(v) = m.messages.get_mut(&ch) {
                        v.retain(|x| x.id != temp);
                    }
                    m.notice = Some(format!("send failed: {e}"));
                }
            }
        }
        ctx.request_repaint();
    });
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

fn net_handle(state: &Arc<Mutex<ClientState>>) -> Option<NetHandle> {
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
