//! Attachments: E2EE file send/receive (C4).
//!
//! Nothing but ciphertext ever leaves the client (ADR 0001): the raw bytes
//! are AES-GCM-encrypted locally by [`Engine::encrypt_file`], the key and
//! nonce ride the Megolm-encrypted [`Envelope::File`] alongside the message
//! row, and the server only ever brokers presigned PUT/GET URLs for the
//! encrypted blob. There are no server-side thumbnails — image decoding,
//! downscaling, and display all happen here, after decrypt.
//!
//! Threading contract (the UI thread never blocks on files, dialogs,
//! crypto, or network):
//!
//! - `rfd` native dialogs run on their own `std::thread` (they block).
//! - `fs::read` + `encrypt_file` run on that same dialog thread (CPU-bound
//!   file work off the UI thread; the dialog already parked it).
//! - Network + `spawn_blocking` decode/decrypt run on the tokio runtime.
//! - Decoded images cross back to the UI thread through an `mpsc` channel
//!   drained by [`drain_decoded`]; textures are created only on the UI
//!   thread (egui requirement).
//!
//! Memory and disk posture:
//!
//! - RAM keeps only the decoded-and-downscaled (≤ [`MAX_DECODE_PX`] px)
//!   RGBA thumbnails — never decrypted originals.
//! - The disk cache under the data dir stores the still-ENCRYPTED bytes
//!   (one file per attachment id); plaintext is only ever written when the
//!   user explicitly Saves or Opens.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use eframe::egui;

use bysyc_common::protocol::{
    AttachmentMeta, CreateAttachmentRequest, MessageDto, MessageKind, SendMessageRequest,
};

use crate::crypto::{Engine, Envelope};
use crate::net::{self, Net};
use crate::state::{
    ClientState, MainState, Phase, UploadPhase, UploadStatus, file_row_text, guard, human_size,
    is_image_name, now_ms,
};
use crate::store::Store;

use super::main_view::{MainView, net_handle};

/// Hard cap on the raw file we will read (the server caps ciphertext at
/// 50 MiB; AES-GCM adds 28 bytes and the envelope a little more).
pub const MAX_RAW_FILE_BYTES: usize = 48 * 1024 * 1024;
/// Images at or below this decrypted size fetch + decode automatically;
/// bigger ones wait for an explicit "load image" click.
pub const AUTO_IMAGE_BYTES: i64 = 2 * 1024 * 1024;
/// Longest side of a decoded image kept in RAM (display scales it down
/// further); the original stays on disk (encrypted) for Save/Open.
pub const MAX_DECODE_PX: u32 = 1024;
/// Inline thumbnail cap in the chat row (popup gets more).
pub const INLINE_IMAGE_PX: f32 = 256.0;
/// Popup cap — roughly a laptop half-screen.
pub const POPUP_IMAGE_PX: egui::Vec2 = egui::Vec2::new(900.0, 700.0);

/// Fresh upload ids for the progress strip (UI-thread allocated).
static UPLOAD_SEQ: AtomicU64 = AtomicU64::new(1);

// ---------------------------------------------------------------------------
// Send path
// ---------------------------------------------------------------------------

/// "+ attach": open a native file picker, then run the whole send pipeline.
///
/// The picker (and the file read + AES-GCM encrypt, which are both slow
/// enough to matter for 48 MiB) run on a dedicated `std::thread`; the
/// network half continues on the runtime. Progress is tracked in
/// [`MainState::uploads`] keyed by a fresh [`UPLOAD_SEQ`] id.
pub fn begin_attach(
    state: &Arc<Mutex<ClientState>>,
    store: &Arc<Mutex<Store>>,
    rt: &tokio::runtime::Handle,
    ctx: &egui::Context,
    mv: &mut MainView,
    ch: i64,
) {
    // Gather everything the background threads need while still on the UI
    // thread: account id, engine, session generation, temp row id.
    let gather = {
        let st = guard(state);
        st.main()
            .map(|m| (m.account.id, m.engine.clone(), st.ws_generation))
    };
    let Some((me, engine, generation)) = gather else {
        return;
    };
    let Some(engine) = engine else {
        if let Some(m) = guard(state).main_mut() {
            m.notice = Some("crypto engine unavailable — attachments are disabled".into());
        }
        return;
    };

    let temp = mv.temp_id;
    mv.temp_id -= 1;
    let upload_id = UPLOAD_SEQ.fetch_add(1, Ordering::Relaxed);
    if let Some(m) = guard(state).main_mut() {
        m.uploads.push(UploadStatus {
            id: upload_id,
            name: "(picking…)".into(),
            phase: UploadPhase::Picking,
        });
    }

    let state = Arc::clone(state);
    let store = Arc::clone(store);
    let rt = rt.clone();
    let ctx = ctx.clone();

    // rfd's sync dialog parks its thread: never the UI thread (it is a
    // windowed app, which is the one context rfd allows dialogs from any
    // thread).
    std::thread::spawn(move || {
        let Some(path) = rfd::FileDialog::new().pick_file() else {
            drop_upload(&state, upload_id);
            ctx.request_repaint();
            return;
        };
        if !session_alive(&state, generation) {
            drop_upload(&state, upload_id);
            return;
        }

        let name = sanitize_filename(
            &path
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| "file".into()),
        );
        set_upload(&state, upload_id, |u| {
            u.name = name.clone();
            u.phase = UploadPhase::Encrypting;
        });
        ctx.request_repaint();

        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) => {
                fail_upload(&state, upload_id, format!("read: {e}"));
                ctx.request_repaint();
                return;
            }
        };
        if bytes.len() > MAX_RAW_FILE_BYTES {
            fail_upload(
                &state,
                upload_id,
                format!(
                    "file is {} — the limit is {}",
                    human_size(bytes.len() as i64),
                    human_size(MAX_RAW_FILE_BYTES as i64)
                ),
            );
            ctx.request_repaint();
            return;
        }
        let (ciphertext, key_b64, nonce_b64) = match engine.encrypt_file(&bytes) {
            Ok(x) => x,
            Err(e) => {
                fail_upload(&state, upload_id, format!("encrypt: {e}"));
                ctx.request_repaint();
                return;
            }
        };
        ctx.request_repaint();

        // Network half on the runtime.
        let upload = UploadJob {
            me,
            ch,
            generation,
            upload_id,
            temp,
            name,
            size: bytes.len(),
            ciphertext,
            key_b64,
            nonce_b64,
        };
        rt.spawn(upload_and_send(state, store, ctx, engine, upload));
    });
}

/// Everything `upload_and_send` needs, bundled so the async fn's future is
/// plain data + shared state.
struct UploadJob {
    me: i64,
    ch: i64,
    generation: u64,
    upload_id: u64,
    temp: i64,
    name: String,
    /// Decrypted size (envelope `size`); the server sees only ciphertext len.
    size: usize,
    ciphertext: Vec<u8>,
    key_b64: String,
    nonce_b64: String,
}

/// Reserve → presigned PUT → Megolm-encrypted File envelope → message POST.
async fn upload_and_send(
    state: Arc<Mutex<ClientState>>,
    store: Arc<Mutex<Store>>,
    ctx: egui::Context,
    engine: Arc<Engine>,
    job: UploadJob,
) {
    let UploadJob {
        me,
        ch,
        generation,
        upload_id,
        temp,
        name,
        size,
        ciphertext,
        key_b64,
        nonce_b64,
    } = job;

    set_upload(&state, upload_id, |u| u.phase = UploadPhase::Uploading);
    ctx.request_repaint();

    let Some(h) = net_handle(&state) else {
        fail_upload(&state, upload_id, "not connected".into());
        ctx.request_repaint();
        return;
    };

    // 1. Reserve the attachment: the server records id/name/ciphertext-size/
    //    nonce (all non-secret) and hands back a presigned PUT URL.
    let created = match h
        .net
        .create_attachment(&CreateAttachmentRequest {
            name: name.clone(),
            size: ciphertext.len() as i64,
            nonce: nonce_b64.clone(),
        })
        .await
    {
        Ok(c) => c,
        Err(e) => {
            fail_upload(&state, upload_id, format!("reserve: {e}"));
            ctx.request_repaint();
            return;
        }
    };
    let att = created.attachment;

    // The File envelope the receivers will decrypt. `size` is the ORIGINAL
    // size — the receiver's "[file: name (size)]" row and auto-image
    // decision use it.
    let envelope = Envelope::File {
        name: name.clone(),
        size: size as i64,
        nonce: nonce_b64.clone(),
        key: key_b64.clone(),
        attachment_id: att.id,
    };

    // Optimistic row, do_send-style: negative temp id, replaced when the
    // POST lands.
    {
        let optimistic = MessageDto {
            id: temp,
            channel_id: ch,
            sender_id: me,
            kind: MessageKind::Chat,
            content: file_row_text(&envelope),
            reply_to: None,
            attachment: Some(att.clone()),
            created_at_ms: now_ms(),
        };
        let mut st = guard(&state);
        if let Some(m) = st.main_mut() {
            m.messages.entry(ch).or_default().push(optimistic);
        }
    }

    // 2. PUT the ciphertext to the presigned URL — no Authorization header,
    //    the URL signature IS the authorization; no Content-Type either
    //    (plain byte PUT).
    if let Err(e) = put_presigned(&created.upload_url, &ciphertext).await {
        remove_temp(&state, ch, temp);
        fail_upload(&state, upload_id, format!("upload: {e}"));
        ctx.request_repaint();
        return;
    }
    if !session_alive(&state, generation) {
        // Logged out mid-upload; the whole MainState (temp row included) is
        // already gone or about to be.
        drop_upload(&state, upload_id);
        return;
    }

    // 3. Wrap the key material in the channel's Megolm session (share-first
    //    rule applies exactly as for chat) and POST the message row.
    set_upload(&state, upload_id, |u| u.phase = UploadPhase::Sending);
    ctx.request_repaint();
    match encrypt_share_and_send(
        &state,
        &store,
        &h.net,
        &engine,
        ch,
        &envelope,
        temp,
        Some(att.id),
    )
    .await
    {
        Ok(dto) => {
            let mut st = guard(&state);
            if let Some(m) = st.main_mut() {
                // Our own engine holds no self-import, so act as if we had
                // just decrypted our own File envelope — that is exactly
                // what receivers do.
                m.file_meta.insert(dto.id, envelope);
                set_upload_on(m, upload_id, |u| u.phase = UploadPhase::Done);
            }
        }
        Err(e) => {
            remove_temp(&state, ch, temp);
            fail_upload(&state, upload_id, e);
        }
    }
    ctx.request_repaint();
}

/// The encrypted send path shared by the chat composer and attachments:
/// Megolm-encrypt `envelope`, honor the share-first rule (bootstrap or
/// rotation share goes out strictly BEFORE the message POST), then POST and
/// reconcile the optimistic temp row.
///
/// On `Err` nothing is cleaned up — the caller owns the temp row and
/// decides what the user sees.
pub(crate) async fn encrypt_share_and_send(
    state: &Arc<Mutex<ClientState>>,
    store: &Arc<Mutex<Store>>,
    net: &Net,
    engine: &Arc<Engine>,
    channel_id: i64,
    envelope: &Envelope,
    temp: i64,
    attachment_id: Option<i64>,
) -> Result<MessageDto, String> {
    // Everything crypto needs, gathered under one state lock up front
    // (do_send's pattern; never the reverse order).
    let gather = {
        let st = guard(state);
        st.main().map(|m| {
            (
                m.channel_peer_ids(channel_id),
                !m.outbound.contains(&channel_id),
                m.outbound_sid.get(&channel_id).cloned(),
            )
        })
    };
    let Some((peers, need_share, known_sid)) = gather else {
        return Err("signed out".into());
    };

    let plaintext = serde_json::to_string(envelope).map_err(|e| format!("serialize: {e}"))?;
    let (sid, ciphertext) = engine
        .megolm_encrypt(channel_id, &plaintext)
        .map_err(|e| format!("encrypt: {e}"))?;

    let rotated = known_sid.as_deref() != Some(sid.as_str());
    if need_share || rotated {
        net::share_session_with_peers(state, engine, net, channel_id, peers).await;
        {
            let mut st = guard(state);
            if let Some(m) = st.main_mut() {
                m.outbound.insert(channel_id);
                m.outbound_sid.insert(channel_id, sid.clone());
            }
        }
        net::persist_outbound(state, store);
    }

    let reply_to = match envelope {
        Envelope::Chat { reply_to, .. } => *reply_to,
        _ => None,
    };
    let req = SendMessageRequest {
        kind: MessageKind::Chat,
        content: ciphertext,
        reply_to,
        attachment_id,
    };
    let dto = net::send_message(net, channel_id, &req).await?;

    {
        // Our own row: the engine deliberately holds no self-import, so
        // store the outgoing plaintext directly (File rows get the
        // "[file: …]" placeholder, same as receivers).
        let s = guard(store);
        let _ = s.append_message(&dto);
        let own_plaintext = match envelope {
            Envelope::Chat { text, .. } => text.clone(),
            Envelope::File { .. } => file_row_text(envelope),
            _ => String::new(),
        };
        if !own_plaintext.is_empty() {
            let _ = s.set_plaintext(dto.id, &own_plaintext);
        }
    }
    let mut st = guard(state);
    if let Some(m) = st.main_mut() {
        m.replace_temp(temp, dto.clone());
    }
    Ok(dto)
}

// ---------------------------------------------------------------------------
// Presigned URL plumbing (no Authorization header — the signature is in it)
// ---------------------------------------------------------------------------

/// Tolerate relative presigned URLs by prefixing the REST base.
fn absolute(base: &str, url: &str) -> String {
    if url.starts_with("http://") || url.starts_with("https://") {
        url.to_string()
    } else if url.starts_with('/') {
        format!("{}{url}", base.trim_end_matches('/'))
    } else {
        format!("{}/{url}", base.trim_end_matches('/'))
    }
}

/// A client WITHOUT our bearer token: presigned endpoints reject (or
/// mis-auth) Authorization headers, so the attachment PUT/GET must not use
/// [`Net`]'s authed plumbing.
fn presigned_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(120))
        .build()
        .unwrap_or_default()
}

async fn put_presigned(url: &str, body: &[u8]) -> Result<(), String> {
    let rsp = presigned_client()
        .put(url)
        .body(body.to_vec())
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if rsp.status().is_success() {
        Ok(())
    } else {
        Err(format!("HTTP {}", rsp.status()))
    }
}

async fn get_presigned(url: &str) -> Result<Vec<u8>, String> {
    let rsp = presigned_client()
        .get(url)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !rsp.status().is_success() {
        return Err(format!("HTTP {}", rsp.status()));
    }
    rsp.bytes()
        .await
        .map(|b| b.to_vec())
        .map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// Encrypted-bytes disk cache (filename = attachment id; ciphertext only)
// ---------------------------------------------------------------------------

fn cache_dir() -> Option<PathBuf> {
    directories::ProjectDirs::from("", "", "bysyc").map(|d| {
        let dir = d.data_dir().join("attachment-cache");
        let _ = std::fs::create_dir_all(&dir);
        dir
    })
}

fn cache_path(attachment_id: i64) -> Option<PathBuf> {
    cache_dir().map(|d| d.join(attachment_id.to_string()))
}

/// The encrypted bytes for an attachment: disk cache first, else a fresh
/// presigned GET (URLs expire, so never cache the URL) which then populates
/// the cache.
async fn ensure_encrypted_bytes(net: &Net, attachment_id: i64) -> Result<Vec<u8>, String> {
    if let Some(p) = cache_path(attachment_id) {
        if let Ok(bytes) = std::fs::read(&p) {
            return Ok(bytes);
        }
    }
    let dl = net.attachment_download_url(attachment_id).await?;
    let url = absolute(net.base(), &dl.url);
    let bytes = get_presigned(&url).await?;
    if let Some(p) = cache_path(attachment_id) {
        let _ = std::fs::write(&p, &bytes);
    }
    Ok(bytes)
}

/// Decrypt the attachment end-to-end: cache/download → AES-GCM decrypt on a
/// blocking thread. Returns the ORIGINAL plaintext bytes (kept only in this
/// task's scope — never in long-lived state).
async fn materialize(
    state: &Arc<Mutex<ClientState>>,
    attachment_id: i64,
    key_b64: &str,
    nonce_b64: &str,
) -> Result<Vec<u8>, String> {
    let h = net_handle(state).ok_or("not connected")?;
    let encrypted = ensure_encrypted_bytes(&h.net, attachment_id).await?;
    let Some(engine) = guard(state).main().and_then(|m| m.engine.clone()) else {
        return Err("crypto engine unavailable".into());
    };
    let (key, nonce) = (key_b64.to_string(), nonce_b64.to_string());
    tokio::task::spawn_blocking(move || {
        engine
            .decrypt_file(&encrypted, &key, &nonce)
            .map_err(|e| format!("decrypt: {e}"))
    })
    .await
    .map_err(|e| format!("worker: {e}"))?
}

// ---------------------------------------------------------------------------
// Image decode (worker) → texture (UI thread)
// ---------------------------------------------------------------------------

/// A decoded, downscaled image crossing from a worker to the UI thread.
pub struct DecodedImage {
    pub attachment_id: i64,
    pub width: u32,
    pub height: u32,
    pub rgba: Vec<u8>,
}

/// Decrypt + decode + downscale on a blocking thread. Only the ≤
/// [`MAX_DECODE_PX`] thumbnail survives; the original plaintext is dropped.
fn decode_thumbnail(
    engine: &Engine,
    encrypted: &[u8],
    key_b64: &str,
    nonce_b64: &str,
    attachment_id: i64,
) -> Result<DecodedImage, String> {
    let plain = engine
        .decrypt_file(encrypted, key_b64, nonce_b64)
        .map_err(|e| format!("decrypt: {e}"))?;
    let img = image::load_from_memory(&plain).map_err(|e| format!("decode: {e}"))?;
    let thumb = img.thumbnail(MAX_DECODE_PX, MAX_DECODE_PX);
    let rgba = thumb.to_rgba8();
    let (width, height) = rgba.dimensions();
    Ok(DecodedImage {
        attachment_id,
        width,
        height,
        rgba: rgba.into_raw(),
    })
}

/// Kick off (or join) the fetch-decode pipeline for one image attachment.
/// The result lands in `mv.image_cache` via [`drain_decoded`].
pub fn fetch_image(
    state: &Arc<Mutex<ClientState>>,
    rt: &tokio::runtime::Handle,
    mv: &MainView,
    ctx: &egui::Context,
    att: &AttachmentMeta,
    key_b64: &str,
    nonce_b64: &str,
) {
    // Gather handle + engine BEFORE the inflight guard, so an early bail
    // cannot strand a permanent inflight marker.
    let Some(h) = net_handle(state) else { return };
    let Some(engine) = guard(state).main().and_then(|m| m.engine.clone()) else {
        return;
    };
    let att_id = att.id;
    let tx = mv.image_tx.clone();
    let ctx = ctx.clone();
    {
        let mut st = guard(state);
        let Some(m) = st.main_mut() else { return };
        if !m.img_inflight.insert(att_id) {
            return; // already loading
        }
        m.img_failed.remove(&att_id);
    }

    let state = Arc::clone(state);
    let (key, nonce) = (key_b64.to_string(), nonce_b64.to_string());
    rt.spawn(async move {
        let result = match ensure_encrypted_bytes(&h.net, att_id).await {
            Ok(encrypted) => {
                // spawn_blocking owns its inputs.
                let engine = Arc::clone(&engine);
                let key = key.clone();
                let nonce = nonce.clone();
                tokio::task::spawn_blocking(move || {
                    decode_thumbnail(&engine, &encrypted, &key, &nonce, att_id)
                })
                .await
                .map_err(|e| format!("worker: {e}"))
                .and_then(|r| r)
            }
            Err(e) => Err(e),
        };
        {
            let mut st = guard(&state);
            if let Some(m) = st.main_mut() {
                m.img_inflight.remove(&att_id);
                if result.is_err() {
                    m.img_failed.insert(att_id);
                }
            }
        }
        match result {
            Ok(img) => {
                let _ = tx.send(img);
            }
            Err(e) => eprintln!("bysyc: attachment {att_id} image decode failed: {e}"),
        }
        ctx.request_repaint();
    });
}

/// Bring finished background decodes onto the UI thread as textures. Must
/// run on the UI thread (textures cannot be created elsewhere).
pub fn drain_decoded(ctx: &egui::Context, mv: &mut MainView) {
    while let Ok(img) = mv.image_rx.try_recv() {
        let color = egui::ColorImage::from_rgba_unmultiplied(
            [img.width as usize, img.height as usize],
            &img.rgba,
        );
        let tex = ctx.load_texture(
            format!("attachment-{}", img.attachment_id),
            color,
            egui::TextureOptions::default(),
        );
        mv.image_cache.insert(img.attachment_id, tex);
    }
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

/// The upload progress strip above the composer. Completed rows vanish;
/// failed ones stay until dismissed.
pub fn uploads_ui(ui: &mut egui::Ui, state: &Arc<Mutex<ClientState>>) {
    let mut dismiss: Option<u64> = None;
    {
        let mut st = guard(state);
        let Some(m) = st.main_mut() else { return };
        m.uploads.retain(|u| u.phase != UploadPhase::Done);
        if m.uploads.is_empty() {
            return;
        }
        for u in &m.uploads {
            let line = match &u.phase {
                UploadPhase::Picking => format!("{} — picking…", u.name),
                UploadPhase::Encrypting => format!("{} — encrypting…", u.name),
                UploadPhase::Uploading => format!("{} — uploading…", u.name),
                UploadPhase::Sending => format!("{} — sending…", u.name),
                UploadPhase::Done => format!("{} — done", u.name),
                UploadPhase::Failed(why) => format!("{} — failed: {why}", u.name),
            };
            ui.horizontal(|ui| {
                if matches!(u.phase, UploadPhase::Failed(_)) {
                    ui.colored_label(egui::Color32::RED, line);
                    if ui.small_button("x").clicked() {
                        dismiss = Some(u.id);
                    }
                } else {
                    ui.weak(line);
                }
            });
        }
        if let Some(id) = dismiss {
            m.uploads.retain(|u| u.id != id);
        }
    }
}

/// One attachment message row body (in place of the plain-text line):
/// an image thumbnail or a file chip, plus Save/Open. `fe` is the decrypted
/// File envelope from [`MainState::file_meta`] (keyed by message id).
#[allow(clippy::too_many_arguments)]
pub fn attachment_row(
    ui: &mut egui::Ui,
    state: &Arc<Mutex<ClientState>>,
    rt: &tokio::runtime::Handle,
    ctx: &egui::Context,
    mv: &mut MainView,
    att: &AttachmentMeta,
    fe: &Envelope,
) {
    let Envelope::File {
        name,
        size,
        nonce,
        key,
        ..
    } = fe
    else {
        return;
    };
    let (key, nonce) = (key.clone(), nonce.clone());
    let shown = format!("📎 {name} ({})", human_size(*size));

    // Chip line: icon, name, size, actions — always.
    ui.horizontal(|ui| {
        ui.strong(shown);
        if ui.small_button("Save").clicked() {
            save_attachment(state, rt, ctx, att.id, att.name.clone(), &key, &nonce);
        }
        if ui.small_button("Open").clicked() {
            open_attachment(state, rt, ctx, att.id, att.name.clone(), &key, &nonce);
        }
    });

    if !is_image_name(name) {
        return;
    }

    // Thumbnail / loading / failure states below the chip.
    if let Some(tex) = mv.image_cache.get(&att.id) {
        let rsp = ui.add(
            egui::Image::new(tex)
                .max_size(egui::Vec2::splat(INLINE_IMAGE_PX))
                .sense(egui::Sense::click()),
        );
        if rsp.clicked() {
            mv.image_popup = Some((att.id, name.clone()));
        }
        return;
    }
    let (inflight, failed) = {
        let st = guard(state);
        match st.main() {
            Some(m) => (
                m.img_inflight.contains(&att.id),
                m.img_failed.contains(&att.id),
            ),
            None => return,
        }
    };
    if inflight {
        ui.horizontal(|ui| {
            ui.add(egui::Spinner::new());
            ui.weak("decrypting…");
        });
        return;
    }
    if failed {
        ui.horizontal(|ui| {
            ui.weak("image unavailable");
            if ui.small_button("retry").clicked() {
                fetch_image(state, rt, mv, ctx, att, &key, &nonce);
            }
        });
        return;
    }
    // Small images load automatically; big ones wait for a click.
    if *size <= AUTO_IMAGE_BYTES {
        fetch_image(state, rt, mv, ctx, att, &key, &nonce);
        ui.horizontal(|ui| {
            ui.add(egui::Spinner::new());
            ui.weak("decrypting…");
        });
    } else if ui.button("load image").clicked() {
        fetch_image(state, rt, mv, ctx, att, &key, &nonce);
    }
}

/// Full-size lightbox for a clicked thumbnail: Save / Open / Close.
pub fn image_popup(
    state: &Arc<Mutex<ClientState>>,
    rt: &tokio::runtime::Handle,
    ctx: &egui::Context,
    mv: &mut MainView,
) {
    let Some((att_id, name)) = mv.image_popup.clone() else {
        return;
    };
    // Reverse lookup: the File envelope carrying this attachment's key.
    let found = {
        let st = guard(state);
        st.main().and_then(|m| {
            m.file_meta
                .values()
                .find(|fe| {
                    matches!(fe, Envelope::File { attachment_id, .. } if *attachment_id == att_id)
                })
                .cloned()
        })
    };
    let Some(fe) = found else {
        mv.image_popup = None; // envelope gone (restarted before decrypt?)
        return;
    };
    let (key, nonce) = match &fe {
        Envelope::File { key, nonce, .. } => (key.clone(), nonce.clone()),
        _ => return,
    };
    // Synthetic meta for fetch/save/open (only the id drives them).
    let att = AttachmentMeta {
        id: att_id,
        name: name.clone(),
        size: 0,
        nonce: String::new(),
    };

    let mut open = true;
    egui::Window::new(name.clone())
        .id(egui::Id::new(("attachment_popup", att_id)))
        .open(&mut open)
        .collapsible(false)
        .show(ctx, |ui| {
            if let Some(tex) = mv.image_cache.get(&att_id) {
                ui.add(egui::Image::new(tex).max_size(POPUP_IMAGE_PX));
            } else {
                let (inflight, failed) = {
                    let st = guard(state);
                    st.main()
                        .map(|m| {
                            (
                                m.img_inflight.contains(&att_id),
                                m.img_failed.contains(&att_id),
                            )
                        })
                        .unwrap_or((false, false))
                };
                if inflight {
                    ui.horizontal(|ui| {
                        ui.add(egui::Spinner::new());
                        ui.weak("decrypting…");
                    });
                } else if failed {
                    ui.weak("image unavailable");
                    if ui.button("retry").clicked() {
                        fetch_image(state, rt, mv, ui.ctx(), &att, &key, &nonce);
                    }
                } else {
                    ui.weak("loading…");
                    fetch_image(state, rt, mv, ui.ctx(), &att, &key, &nonce);
                }
            }
            ui.horizontal(|ui| {
                if ui.button("Save").clicked() {
                    save_attachment(state, rt, ui.ctx(), att_id, name.clone(), &key, &nonce);
                }
                if ui.button("Open").clicked() {
                    open_attachment(state, rt, ui.ctx(), att_id, name.clone(), &key, &nonce);
                }
            });
        });
    if !open {
        mv.image_popup = None;
    }
}

// ---------------------------------------------------------------------------
// Save / Open (explicit export of plaintext — the only path that ever
// writes decrypted bytes to disk)
// ---------------------------------------------------------------------------

/// Save dialog (std thread — it blocks), then decrypt + write.
#[allow(clippy::too_many_arguments)]
fn save_attachment(
    state: &Arc<Mutex<ClientState>>,
    rt: &tokio::runtime::Handle,
    ctx: &egui::Context,
    attachment_id: i64,
    name: String,
    key_b64: &str,
    nonce_b64: &str,
) {
    let state = Arc::clone(state);
    let rt = rt.clone();
    let ctx = ctx.clone();
    let (key, nonce) = (key_b64.to_string(), nonce_b64.to_string());
    std::thread::spawn(move || {
        let Some(path) = rfd::FileDialog::new().set_file_name(&name).save_file() else {
            return;
        };
        rt.spawn(async move {
            match materialize(&state, attachment_id, &key, &nonce).await {
                Ok(bytes) => {
                    if let Err(e) = std::fs::write(&path, &bytes) {
                        notice(&state, format!("save failed: {e}"));
                    }
                }
                Err(e) => notice(&state, format!("save failed: {e}")),
            }
            ctx.request_repaint();
        });
    });
}

/// Decrypt to a temp path and hand it to the OS opener (best-effort).
fn open_attachment(
    state: &Arc<Mutex<ClientState>>,
    rt: &tokio::runtime::Handle,
    ctx: &egui::Context,
    attachment_id: i64,
    name: String,
    key_b64: &str,
    nonce_b64: &str,
) {
    let state = Arc::clone(state);
    let ctx = ctx.clone();
    let path = temp_open_path(&name);
    let (key, nonce) = (key_b64.to_string(), nonce_b64.to_string());
    rt.spawn(async move {
        match materialize(&state, attachment_id, &key, &nonce).await {
            Ok(bytes) => match std::fs::write(&path, &bytes) {
                Ok(()) => open_with_os(&path),
                Err(e) => notice(&state, format!("open failed: {e}")),
            },
            Err(e) => notice(&state, format!("open failed: {e}")),
        }
        ctx.request_repaint();
    });
}

/// Temp file for Open: unique per call so two opens of the same name never
/// clobber each other.
fn temp_open_path(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join("bysyc-open");
    let _ = std::fs::create_dir_all(&dir);
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    dir.join(format!("{stamp}-{}", sanitize_filename(name)))
}

/// Best-effort "open with the default app".
fn open_with_os(path: &std::path::Path) {
    #[cfg(target_os = "macos")]
    let spawned = std::process::Command::new("open").arg(path).spawn();
    #[cfg(target_os = "windows")]
    let spawned = std::process::Command::new("cmd")
        .args(["/C", "start", "", path])
        .spawn();
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    let spawned = std::process::Command::new("xdg-open").arg(path).spawn();
    if let Err(e) = spawned {
        eprintln!("bysyc: OS opener failed for {}: {e}", path.display());
    }
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

/// Make a user-supplied filename safe as a single path component.
fn sanitize_filename(name: &str) -> String {
    let mapped: String = name
        .chars()
        .map(|c| match c {
            '/' | '\\' | ':' | '\0' => '_',
            _ => c,
        })
        .collect();
    let mut s: String = mapped.chars().take(120).collect();
    s.truncate(120);
    s.trim_matches('.').to_string()
}

/// Did the session that spawned this task survive (no logout/re-login)?
fn session_alive(state: &Arc<Mutex<ClientState>>, generation: u64) -> bool {
    let st = guard(state);
    matches!(st.phase, Phase::LoggedIn(_)) && st.ws_generation == generation
}

fn set_upload(state: &Arc<Mutex<ClientState>>, id: u64, f: impl FnOnce(&mut UploadStatus)) {
    let mut st = guard(state);
    if let Some(m) = st.main_mut() {
        set_upload_on(m, id, f);
    }
}

fn set_upload_on(m: &mut MainState, id: u64, f: impl FnOnce(&mut UploadStatus)) {
    if let Some(u) = m.uploads.iter_mut().find(|u| u.id == id) {
        f(u);
    }
}

fn fail_upload(state: &Arc<Mutex<ClientState>>, id: u64, why: String) {
    let mut st = guard(state);
    if let Some(m) = st.main_mut() {
        set_upload_on(m, id, |u| u.phase = UploadPhase::Failed(why));
    }
}

fn drop_upload(state: &Arc<Mutex<ClientState>>, id: u64) {
    let mut st = guard(state);
    if let Some(m) = st.main_mut() {
        m.uploads.retain(|u| u.id != id);
    }
}

fn remove_temp(state: &Arc<Mutex<ClientState>>, ch: i64, temp: i64) {
    let mut st = guard(state);
    if let Some(m) = st.main_mut() {
        if let Some(v) = m.messages.get_mut(&ch) {
            v.retain(|x| x.id != temp);
        }
    }
}

fn notice(state: &Arc<Mutex<ClientState>>, msg: String) {
    if let Some(m) = guard(state).main_mut() {
        m.notice = Some(msg);
    }
}

// ---------------------------------------------------------------------------
// Tests (pure logic; GUI paths are compile-checked)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitized_names_are_single_path_components() {
        assert_eq!(sanitize_filename("cat.png"), "cat.png");
        assert_eq!(sanitize_filename("photo 2.JPG"), "photo 2.JPG");
        // Path separators and friends neutralized, edge dots trimmed.
        assert_eq!(sanitize_filename("../../etc/passwd"), "_.._etc_passwd");
        assert_eq!(sanitize_filename("a/b\\c:d"), "a_b_c_d");
        assert_eq!(sanitize_filename("..hidden.."), "hidden");
        // No panics on weird input; length capped.
        let long = "x".repeat(500);
        assert_eq!(sanitize_filename(&long).len(), 120);
        assert_eq!(sanitize_filename(""), "");
    }

    #[test]
    fn cache_paths_are_stable_per_attachment() {
        // ProjectDirs exists on all our targets; on the odd platform
        // without one the cache simply disables.
        let Some(a) = cache_path(7) else { return };
        let Some(b) = cache_path(8) else { return };
        assert_eq!(a, cache_path(7).unwrap());
        assert_ne!(a, b);
        assert!(a.ends_with("7"), "one file per attachment id");
        // All cache entries live directly under the cache dir.
        assert_eq!(a.parent(), b.parent());
    }

    #[test]
    fn presigned_urls_tolerate_relative_forms() {
        assert_eq!(
            absolute("http://x", "https://cdn/y?sig=1"),
            "https://cdn/y?sig=1"
        );
        assert_eq!(absolute("http://x", "http://cdn/y"), "http://cdn/y");
        assert_eq!(absolute("http://x/", "/z"), "http://x/z");
        assert_eq!(absolute("http://x", "z"), "http://x/z");
    }
}
