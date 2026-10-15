//! Attachments: two send flows, one render path (C4).
//!
//! **E2E-encrypted files** — arbitrary files keep the original C4 posture:
//! nothing but ciphertext ever leaves the client (ADR 0001). The raw bytes
//! are AES-GCM-encrypted locally by [`Engine::encrypt_file`], the key and
//! nonce ride the Megolm-encrypted [`Envelope::File`] alongside the message
//! row, and the server only ever brokers presigned PUT/GET URLs for the
//! encrypted blob.
//!
//! **Server-side images** — png/jpeg/webp/bmp and single-frame gif inputs
//! are re-encoded locally to lossy WebP ([`WEBP_QUALITY`]; re-encoding
//! goes through raw pixels, so ALL EXIF/ICC/metadata is dropped — there is
//! no metadata path into the encoder), renamed to a random
//! `img_<hex>.webp` (the original filename never leaves the device), and
//! POSTed as plaintext bytes to `/attachments/image`, which validates the
//! WebP magic and stores them itself — no presigned PUT. Privacy tradeoff,
//! deliberate: these images are NOT end-to-end encrypted; the server (and
//! anyone who can read its object storage) sees them. What stays E2EE is
//! the message context around them (the [`Envelope::File`] still rides
//! Megolm — with empty key/nonce — so only channel members learn an image
//! was sent). Decoding and downscaling still happen here; there are no
//! server-side thumbnails. Animated GIFs cannot be re-encoded (no animated
//! WebP encoder), so they keep the encrypted file flow verbatim.
//!
//! Both flows persist the decrypted [`Envelope::File`] in the local store
//! at send/decrypt time, and [`MainState::backfill_plaintexts`] rebuilds
//! `file_meta` from it after a restart — without that, the chip and
//! preview would vanish (our own rows can never be re-decrypted: the
//! engine holds no Megolm self-import).
//!
//! Threading contract (the UI thread never blocks on files, dialogs,
//! crypto, or network):
//!
//! - `rfd` native dialogs run on their own `std::thread` (they block).
//! - `fs::read` + WebP re-encode / `encrypt_file` run on a dedicated
//!   `std::thread` kicked off by the composer's send flush (CPU-bound file
//!   work off the UI thread).
//! - Network + `spawn_blocking` decode/decrypt run on the tokio runtime.
//! - Decoded images cross back to the UI thread through an `mpsc` channel
//!   drained by [`drain_decoded`]; textures are created only on the UI
//!   thread (egui requirement).
//! - Save/Open exports ride the same rails (dialog `std::thread` → runtime
//!   → `spawn_blocking` write/opener) and report progress as strip rows in
//!   [`FILE_OPS`], which outlives a logout that wipes `MainState`
//!   mid-export so the row can still say how it ended.
//!
//! Memory and disk posture:
//!
//! - RAM keeps only the decoded-and-downscaled (≤ [`MAX_DECODE_PX`] px)
//!   RGBA thumbnails — never decrypted originals.
//! - The disk cache under the data dir (one file per attachment id) stores
//!   the bytes exactly as they sit in object storage: still-ENCRYPTED
//!   ciphertext for E2EE files, the already-server-visible WebP for
//!   server-side images. Plaintext originals are only ever written when
//!   the user explicitly Saves or Opens.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

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
/// Lossy WebP quality for the server-side image flow (libwebp's 0–100
/// scale; 78 sits just under libwebp's default of 75–80 territory).
pub const WEBP_QUALITY: f32 = 78.0;
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
/// Fresh Save/Open ids for the export rows of the same strip.
static FILE_OP_SEQ: AtomicU64 = AtomicU64::new(1);

/// Upload ids the user cancelled from the strip ("x" on an active row). The
/// pipeline consumes the flag at its phase boundaries; a presigned PUT
/// already on the wire is best-effort — it finishes, we just stop tracking.
static CANCELLED_UPLOADS: LazyLock<Mutex<HashSet<u64>>> =
    LazyLock::new(|| Mutex::new(HashSet::new()));

// ---------------------------------------------------------------------------
// Send path
// ---------------------------------------------------------------------------

/// One file queued in the composer, waiting to ride the channel's next
/// send (attach pick or OS drop). Nothing is read or sent until then.
pub struct PendingFile {
    pub path: PathBuf,
    /// Display name, sanitized exactly as the send pipeline will send it.
    pub name: String,
}

/// "+ attach": open a native file picker and queue the chosen file with
/// this channel's composer — nothing sends until Enter / the send button
/// flushes the pending strip (see the chat view's send path).
///
/// rfd's sync dialog parks its thread, so it is never the UI thread (it is
/// a windowed app, which is the one context rfd allows dialogs from any
/// thread). The channel is captured at click time: the dialog may outlive
/// a channel switch.
pub fn begin_attach(ctx: &egui::Context, mv: &MainView, ch: i64) {
    let tx = mv.attach_tx.clone();
    let ctx = ctx.clone();
    std::thread::spawn(move || {
        if let Some(path) = rfd::FileDialog::new().pick_file() {
            let _ = tx.send((ch, path));
        }
        ctx.request_repaint();
    });
}

/// Queue one file with a channel's composer (attach pick or OS drop).
pub fn add_pending(mv: &mut MainView, ch: i64, path: PathBuf) {
    let name = sanitize_filename(
        &path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "file".into()),
    );
    mv.pending.entry(ch).or_default().push(PendingFile { path, name });
}

/// Files dropped onto the window this frame queue with the viewed
/// channel's composer — the same pending state the attach button feeds.
/// egui hands dropped files over for a single frame only, so this runs
/// every frame; entries without a usable plain-file path (directories) are
/// skipped. Nothing here sends.
pub fn add_dropped(ui: &egui::Ui, mv: &mut MainView, ch: i64) {
    for file in ui.input(|i| i.raw.dropped_files.clone()) {
        let path = file.path().to_path_buf();
        if path.is_file() {
            add_pending(mv, ch, path);
        }
    }
}

/// The pending-attachment strip above the composer: one row per queued
/// file, removable with "x", sent with the channel's next send.
pub fn pending_ui(ui: &mut egui::Ui, mv: &mut MainView, ch: i64) {
    let mut remove: Option<usize> = None;
    let Some(files) = mv.pending.get(&ch) else {
        return;
    };
    for (idx, f) in files.iter().enumerate() {
        ui.horizontal(|ui| {
            ui.weak(format!("📎 {}", f.name));
            if ui.small_button("x").clicked() {
                remove = Some(idx);
            }
        });
    }
    if let Some(idx) = remove
        && let Some(files) = mv.pending.get_mut(&ch)
    {
        files.remove(idx);
    }
}

/// Send one queued composer attachment: read, then either re-encode to
/// lossy WebP or AES-GCM encrypt on a dedicated `std::thread` (all slow
/// enough to matter for 48 MiB), then the network half continues on the
/// runtime via [`upload_image_and_send`] or [`upload_and_send`].
/// Progress is tracked in [`MainState::uploads`] keyed by a fresh
/// [`UPLOAD_SEQ`] id.
#[allow(clippy::too_many_arguments)]
pub fn queue_upload(
    state: &Arc<Mutex<ClientState>>,
    store: &Arc<Mutex<Store>>,
    rt: &tokio::runtime::Handle,
    ctx: &egui::Context,
    mv: &mut MainView,
    ch: i64,
    file: PendingFile,
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
            name: file.name.clone(),
            phase: UploadPhase::Encrypting,
        });
    }

    let state = Arc::clone(state);
    let store = Arc::clone(store);
    let rt = rt.clone();
    let ctx = ctx.clone();

    std::thread::spawn(move || {
        if !session_alive(&state, generation) {
            drop_upload(&state, upload_id);
            return;
        }

        let bytes = match std::fs::read(&file.path) {
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
        if upload_stopped(&state, upload_id, ch, temp) {
            ctx.request_repaint();
            return;
        }
        // Image inputs take the server-side WebP flow: re-encode right here
        // (CPU-bound, same thread) and hand off to the image upload task.
        // Non-images and animated GIFs fall through to the encrypted flow.
        // The re-encode never compares sizes — the WebP is sent even when
        // it is the larger of the two.
        if let Some(webp) = maybe_webp(&bytes) {
            ctx.request_repaint();
            if upload_stopped(&state, upload_id, ch, temp) {
                ctx.request_repaint();
                return;
            }
            let job = ImageUploadJob {
                me,
                ch,
                generation,
                upload_id,
                temp,
                name: random_image_name(),
                webp,
            };
            rt.spawn(upload_image_and_send(state, store, ctx, engine, job));
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
        if upload_stopped(&state, upload_id, ch, temp) {
            ctx.request_repaint();
            return;
        }

        // Network half on the runtime.
        let upload = UploadJob {
            me,
            ch,
            generation,
            upload_id,
            temp,
            name: file.name,
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
    if upload_stopped(&state, upload_id, ch, temp) {
        ctx.request_repaint();
        return;
    }

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

    if upload_stopped(&state, upload_id, ch, temp) {
        // Cancelled after presign: the reserved id simply never receives
        // its ciphertext (an orphan the server never exposes).
        ctx.request_repaint();
        return;
    }

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
    if upload_stopped(&state, upload_id, ch, temp) {
        // The PUT already went out — best-effort: pull the optimistic row
        // and stop tracking instead of posting the message that would
        // reveal the file.
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
            clear_upload_cancel(upload_id);
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
pub async fn encrypt_share_and_send(
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
        // File envelopes outlive the process: persist the decrypted JSON so
        // backfill can rebuild file_meta after a restart (our own rows can
        // never be re-decrypted — the engine holds no Megolm self-import).
        if matches!(envelope, Envelope::File { .. })
            && let Ok(json) = envelope.to_json()
        {
            let _ = s.set_file_envelope(dto.id, &json);
        }
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
// Server-side image flow: re-encode → plaintext WebP → POST /attachments/image
// ---------------------------------------------------------------------------

/// Re-encode an image input as lossy WebP, if it qualifies for the
/// server-side image flow: png / jpeg / webp / bmp and single-frame gif.
/// Animated GIFs (more than one frame) return `None` — there is no animated
/// WebP encoder here, so they keep the encrypted file flow. A decode or
/// re-encode failure also returns `None`, falling back rather than failing
/// the send.
fn maybe_webp(bytes: &[u8]) -> Option<Vec<u8>> {
    use image::ImageFormat::{Bmp, Gif, Jpeg, Png, WebP};
    match image::guess_format(bytes).ok()? {
        Png | Jpeg | WebP | Bmp => reencode_webp(bytes),
        Gif if !is_animated_gif(bytes) => reencode_webp(bytes),
        _ => None,
    }
}

/// GIFs with more than one frame. Conservative on errors: a GIF we cannot
/// decode is treated as animated (the encrypted flow can always carry it).
fn is_animated_gif(bytes: &[u8]) -> bool {
    use image::AnimationDecoder;
    image::codecs::gif::GifDecoder::new(std::io::Cursor::new(bytes))
        .map(|dec| dec.into_frames().count() > 1)
        .unwrap_or(true)
}

/// Decode to raw pixels and re-encode as lossy WebP at [`WEBP_QUALITY`].
/// Going through pixels is also the metadata story: EXIF/ICC/text chunks
/// have no path into this encoder, so none can survive. Alpha is preserved
/// when present.
fn reencode_webp(bytes: &[u8]) -> Option<Vec<u8>> {
    let img = match image::load_from_memory(bytes) {
        Ok(img) => img,
        Err(e) => {
            eprintln!("bysyc: image decode for WebP re-encode failed: {e}");
            return None;
        }
    };
    let (width, height) = (img.width(), img.height());
    let encoded = if img.color().has_alpha() {
        let rgba = img.to_rgba8();
        webp::Encoder::from_rgba(rgba.as_raw(), width, height).encode(WEBP_QUALITY)
    } else {
        let rgb = img.to_rgb8();
        webp::Encoder::from_rgb(rgb.as_raw(), width, height).encode(WEBP_QUALITY)
    };
    Some(encoded.to_vec())
}

/// Random server-side image name, `img_<16 hex chars>.webp` from 8 random
/// bytes. The original filename never leaves the device on this flow.
fn random_image_name() -> String {
    use rand::Rng;
    let mut b = [0u8; 8];
    rand::rng().fill_bytes(&mut b);
    let hex: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!("img_{hex}.webp")
}

/// Everything `upload_image_and_send` needs: the re-encoded WebP plus its
/// send context — [`UploadJob`]'s shape minus the crypto fields (there is
/// nothing to encrypt client-side on this flow).
struct ImageUploadJob {
    me: i64,
    ch: i64,
    generation: u64,
    upload_id: u64,
    temp: i64,
    /// Random `img_<hex>.webp`, generated at queue time.
    name: String,
    webp: Vec<u8>,
}

/// POST the raw WebP body to `/attachments/image` — the server validates
/// the WebP magic, assigns its own name, and stores the bytes; no presigned
/// PUT. Then wrap an empty-key File envelope in Megolm and POST the message
/// row exactly like the encrypted flow. The envelope still rides Megolm so
/// only channel members learn an image was sent; the image BYTES are
/// server-visible by design (see the module doc's privacy tradeoff).
async fn upload_image_and_send(
    state: Arc<Mutex<ClientState>>,
    store: Arc<Mutex<Store>>,
    ctx: egui::Context,
    engine: Arc<Engine>,
    job: ImageUploadJob,
) {
    let ImageUploadJob {
        me,
        ch,
        generation,
        upload_id,
        temp,
        name,
        webp,
    } = job;

    set_upload(&state, upload_id, |u| u.phase = UploadPhase::Uploading);
    ctx.request_repaint();

    let Some(h) = net_handle(&state) else {
        fail_upload(&state, upload_id, "not connected".into());
        ctx.request_repaint();
        return;
    };
    if upload_stopped(&state, upload_id, ch, temp) {
        ctx.request_repaint();
        return;
    }

    let att = match h.net.upload_image(&webp).await {
        Ok(r) => r.attachment,
        Err(e) => {
            fail_upload(&state, upload_id, format!("image upload: {e}"));
            ctx.request_repaint();
            return;
        }
    };
    if upload_stopped(&state, upload_id, ch, temp) {
        // Cancelled after the store landed: no message ever references the
        // object, so it is just an orphan the server never exposes.
        ctx.request_repaint();
        return;
    }
    if !session_alive(&state, generation) {
        // Logged out mid-send; the whole MainState (temp row included) is
        // already gone or about to be.
        drop_upload(&state, upload_id);
        return;
    }

    // Empty key/nonce marks "not client-encrypted" — receivers (and we,
    // after a restart) skip the decrypt step and decode the stored bytes
    // directly. `size` is what receivers will actually download: the WebP.
    let envelope = Envelope::File {
        name: name.clone(),
        size: webp.len() as i64,
        nonce: String::new(),
        key: String::new(),
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
                // Same self-decrypt fiction as the encrypted flow: receivers
                // would have this envelope in file_meta, so we do too.
                m.file_meta.insert(dto.id, envelope);
                set_upload_on(m, upload_id, |u| u.phase = UploadPhase::Done);
            }
            clear_upload_cancel(upload_id);
        }
        Err(e) => {
            remove_temp(&state, ch, temp);
            fail_upload(&state, upload_id, e);
        }
    }
    ctx.request_repaint();
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
// Attachment-bytes disk cache (filename = attachment id; bytes as stored)
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

/// The bytes of an attachment exactly as they sit in object storage —
/// still-encrypted ciphertext for E2EE files, the server-visible WebP for
/// server-side images: disk cache first, else a fresh presigned GET (URLs
/// expire, so never cache the URL) which then populates the cache.
async fn ensure_bytes(net: &Net, attachment_id: i64) -> Result<Vec<u8>, String> {
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

/// Produce the exportable bytes for an export row: cache/download → (E2EE
/// attachments only) AES-GCM decrypt on a blocking thread, moving the row
/// through its Downloading/Decrypting phases as it goes. Server-side images
/// (`encrypted == false`) return the stored WebP as-is — nothing to
/// decrypt. Returns the ORIGINAL plaintext bytes (kept only in this task's
/// scope — never in long-lived state).
async fn materialize(
    ctx: &egui::Context,
    op_id: u64,
    state: &Arc<Mutex<ClientState>>,
    attachment_id: i64,
    encrypted: bool,
    key_b64: &str,
    nonce_b64: &str,
) -> Result<Vec<u8>, String> {
    let h = net_handle(state).ok_or("not connected")?;
    set_file_op_phase(op_id, FileOpPhase::Downloading);
    ctx.request_repaint();
    let stored = ensure_bytes(&h.net, attachment_id).await?;
    if !encrypted {
        return Ok(stored);
    }
    let Some(engine) = guard(state).main().and_then(|m| m.engine.clone()) else {
        return Err("crypto engine unavailable".into());
    };
    let (key, nonce) = (key_b64.to_string(), nonce_b64.to_string());
    set_file_op_phase(op_id, FileOpPhase::Decrypting);
    ctx.request_repaint();
    tokio::task::spawn_blocking(move || {
        engine
            .decrypt_file(&stored, &key, &nonce)
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
    decode_thumbnail_bytes(&plain, attachment_id)
}

/// Decode + downscale already-plaintext image bytes (the server-side WebP
/// flow skips the decrypt step entirely).
fn decode_thumbnail_bytes(plain: &[u8], attachment_id: i64) -> Result<DecodedImage, String> {
    let img = image::load_from_memory(plain).map_err(|e| format!("decode: {e}"))?;
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
    // cannot strand a permanent inflight marker. The engine is only needed
    // for E2EE attachments; server-side images decode without it.
    let Some(h) = net_handle(state) else { return };
    let engine = if att.encrypted {
        let Some(e) = guard(state).main().and_then(|m| m.engine.clone()) else {
            return;
        };
        Some(e)
    } else {
        None
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
    let encrypted = att.encrypted;
    rt.spawn(async move {
        let result = match ensure_bytes(&h.net, att_id).await {
            Ok(stored) => {
                // spawn_blocking owns its inputs.
                let engine = engine.clone();
                let key = key.clone();
                let nonce = nonce.clone();
                tokio::task::spawn_blocking(move || {
                    if encrypted {
                        let engine = engine.as_deref().ok_or("crypto engine unavailable")?;
                        decode_thumbnail(engine, &stored, &key, &nonce, att_id)
                    } else {
                        // Server-side image: the stored bytes ARE the image.
                        decode_thumbnail_bytes(&stored, att_id)
                    }
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

/// The progress strip above the composer: upload rows on top, Save/Open
/// export rows underneath. Completed uploads vanish; failed ones stay until
/// dismissed; the "x" on an active upload row cancels it at its next
/// checkpoint (best-effort — see [`CANCELLED_UPLOADS`]).
pub fn uploads_ui(ui: &mut egui::Ui, state: &Arc<Mutex<ClientState>>) {
    upload_rows(ui, state);
    file_ops_ui(ui);
}

/// The upload half of [`uploads_ui`].
fn upload_rows(ui: &mut egui::Ui, state: &Arc<Mutex<ClientState>>) {
    let mut dismiss: Option<u64> = None;
    let mut cancel: Option<u64> = None;
    {
        let mut st = guard(state);
        let Some(m) = st.main_mut() else { return };
        m.uploads.retain(|u| u.phase != UploadPhase::Done);
        if m.uploads.is_empty() {
            return;
        }
        for u in &m.uploads {
            let line = match &u.phase {
                UploadPhase::Encrypting => format!("{} — preparing…", u.name),
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
                    if ui.small_button("x").clicked() {
                        cancel = Some(u.id);
                    }
                }
            });
        }
        if let Some(id) = cancel {
            // Flag the pipeline for its next checkpoint; the row stops
            // being tracked right away.
            request_upload_cancel(id);
            m.uploads.retain(|u| u.id != id);
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
    let encrypted = att.encrypted;
    let shown = format!("📎 {name} ({})", human_size(*size));

    // Chip line: icon, name, size, actions — always.
    ui.horizontal(|ui| {
        ui.strong(shown);
        if ui.small_button("Save").clicked() {
            save_attachment(
                state,
                rt,
                ctx,
                att.id,
                att.name.clone(),
                encrypted,
                &key,
                &nonce,
            );
        }
        if ui.small_button("Open").clicked() {
            open_attachment(
                state,
                rt,
                ctx,
                att.id,
                att.name.clone(),
                encrypted,
                &key,
                &nonce,
            );
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
            ui.weak("loading…");
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
            ui.weak("loading…");
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
    // Empty key in the envelope marks the server-side image flow (nothing
    // to decrypt — see upload_image_and_send).
    let (key, nonce, encrypted) = match &fe {
        Envelope::File { key, nonce, .. } => (key.clone(), nonce.clone(), !key.is_empty()),
        _ => return,
    };
    // Synthetic meta for fetch/save/open (only the id drives them).
    let att = AttachmentMeta {
        id: att_id,
        name: name.clone(),
        size: 0,
        nonce: String::new(),
        encrypted,
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
                        ui.weak("loading…");
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
                    save_attachment(
                        state,
                        rt,
                        ui.ctx(),
                        att_id,
                        name.clone(),
                        encrypted,
                        &key,
                        &nonce,
                    );
                }
                if ui.button("Open").clicked() {
                    open_attachment(
                        state,
                        rt,
                        ui.ctx(),
                        att_id,
                        name.clone(),
                        encrypted,
                        &key,
                        &nonce,
                    );
                }
            });
        });
    if !open {
        mv.image_popup = None;
    }
}

// ---------------------------------------------------------------------------
// Save/Open export rows (the strip's second half, under the uploads)
// ---------------------------------------------------------------------------

/// Where one Save/Open export is right now; the strip renders it as
/// "name — label…" beside a spinner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FileOpPhase {
    /// Native save dialog is open (worker thread).
    Choosing,
    /// Encrypted-cache read or presigned GET.
    Downloading,
    /// AES-GCM decrypt on a blocking thread.
    Decrypting,
    /// Writing the plaintext to the chosen path (Save).
    Saving,
    /// Writing the temp copy and handing it to the OS opener (Open).
    Opening,
}

impl FileOpPhase {
    fn label(self) -> &'static str {
        match self {
            FileOpPhase::Choosing => "choosing destination…",
            FileOpPhase::Downloading => "downloading…",
            FileOpPhase::Decrypting => "decrypting…",
            FileOpPhase::Saving => "saving…",
            FileOpPhase::Opening => "opening…",
        }
    }
}

/// Terminal states of one export row.
#[derive(Clone, Debug, PartialEq, Eq)]
enum FileOpStatus {
    /// In flight (phase label + spinner).
    Working(FileOpPhase),
    /// Success — lingers [`FILE_OP_DONE_LINGER`] as the confirmation: Save
    /// names the destination it wrote, Open just says it handed the file
    /// off to the OS.
    Done(String),
    /// Terminal failure (dismissible, like a failed upload row).
    Failed(String),
}

/// One Save/Open row of the progress strip.
struct FileOp {
    id: u64,
    name: String,
    status: FileOpStatus,
    /// When the current status was set; expires `Done` rows.
    since: Instant,
}

/// Live Save/Open exports. Module-local on purpose: an export still running
/// when a logout wipes `MainState` (whose `uploads` die with it) must be
/// able to report how it ended, and background tasks address their row by
/// id, not by session.
static FILE_OPS: LazyLock<Mutex<Vec<FileOp>>> = LazyLock::new(|| Mutex::new(Vec::new()));

/// How long a finished export row lingers as its confirmation.
const FILE_OP_DONE_LINGER: Duration = Duration::from_secs(6);

fn file_ops() -> std::sync::MutexGuard<'static, Vec<FileOp>> {
    FILE_OPS.lock().unwrap_or_else(|p| p.into_inner())
}

/// First row state for a fresh export; returns the id its task updates.
fn push_file_op(name: &str, phase: FileOpPhase) -> u64 {
    let id = FILE_OP_SEQ.fetch_add(1, Ordering::Relaxed);
    file_ops().push(FileOp {
        id,
        name: name.to_string(),
        status: FileOpStatus::Working(phase),
        since: Instant::now(),
    });
    id
}

/// `Working` → `Working` (a phase boundary was crossed).
fn set_file_op_phase(id: u64, phase: FileOpPhase) {
    if let Some(op) = file_ops().iter_mut().find(|o| o.id == id) {
        op.status = FileOpStatus::Working(phase);
        op.since = Instant::now();
    }
}

/// `Working` → `Done` (the Save/Open confirmation).
fn finish_file_op(id: u64, msg: String) {
    if let Some(op) = file_ops().iter_mut().find(|o| o.id == id) {
        op.status = FileOpStatus::Done(msg);
        op.since = Instant::now();
    }
}

/// `Working` → `Failed`: red strip row plus the app-wide notice (the error
/// surface Save/Open already had before these rows existed).
fn fail_file_op(state: &Arc<Mutex<ClientState>>, id: u64, context: &str, why: String) {
    let msg = format!("{context}: {why}");
    if let Some(op) = file_ops().iter_mut().find(|o| o.id == id) {
        op.status = FileOpStatus::Failed(msg.clone());
        op.since = Instant::now();
    }
    notice(state, msg);
}

/// Remove a row outright (the user closed the save dialog).
fn drop_file_op(id: u64) {
    file_ops().retain(|o| o.id != id);
}

/// Export rows under the upload rows: spinner while an export runs, a short
/// green confirmation when it lands, red + dismiss when it fails.
fn file_ops_ui(ui: &mut egui::Ui) {
    let mut ops = file_ops();
    ops.retain(|o| {
        !matches!(o.status, FileOpStatus::Done(_)) || o.since.elapsed() < FILE_OP_DONE_LINGER
    });
    if ops.is_empty() {
        return;
    }
    let mut dismiss: Option<u64> = None;
    for op in &*ops {
        ui.horizontal(|ui| match &op.status {
            FileOpStatus::Working(phase) => {
                ui.add(egui::Spinner::new());
                ui.weak(format!("{} — {}", op.name, phase.label()));
            }
            FileOpStatus::Done(msg) => {
                ui.colored_label(egui::Color32::GREEN, format!("{} — {msg}", op.name));
                // Let the row expire on its own, input or no input.
                ui.ctx()
                    .request_repaint_after(FILE_OP_DONE_LINGER.saturating_sub(op.since.elapsed()));
            }
            FileOpStatus::Failed(why) => {
                ui.colored_label(egui::Color32::RED, format!("{} — failed: {why}", op.name));
                if ui.small_button("x").clicked() {
                    dismiss = Some(op.id);
                }
            }
        });
    }
    if let Some(id) = dismiss {
        ops.retain(|o| o.id != id);
    }
}

// ---------------------------------------------------------------------------
// Save / Open (explicit export of plaintext — the only path that ever
// writes decrypted bytes to disk; every phase is a strip row)
// ---------------------------------------------------------------------------

/// Save dialog (std thread — it blocks), then download + (E2EE only)
/// decrypt + write, reported as a strip row: spinner through each phase,
/// then the "saved to …" confirmation or the failure.
#[allow(clippy::too_many_arguments)]
fn save_attachment(
    state: &Arc<Mutex<ClientState>>,
    rt: &tokio::runtime::Handle,
    ctx: &egui::Context,
    attachment_id: i64,
    name: String,
    encrypted: bool,
    key_b64: &str,
    nonce_b64: &str,
) {
    let state = Arc::clone(state);
    let rt = rt.clone();
    let ctx = ctx.clone();
    let (key, nonce) = (key_b64.to_string(), nonce_b64.to_string());
    let op_id = push_file_op(&name, FileOpPhase::Choosing);
    std::thread::spawn(move || {
        let Some(path) = rfd::FileDialog::new().set_file_name(&name).save_file() else {
            drop_file_op(op_id);
            ctx.request_repaint();
            return;
        };
        ctx.request_repaint();
        rt.spawn(async move {
            let result = match materialize(
                &ctx,
                op_id,
                &state,
                attachment_id,
                encrypted,
                &key,
                &nonce,
            )
            .await
            {
                Ok(bytes) => {
                    set_file_op_phase(op_id, FileOpPhase::Saving);
                    ctx.request_repaint();
                    let shown = path.display().to_string();
                    match tokio::task::spawn_blocking(move || {
                        std::fs::write(&path, &bytes).map_err(|e| format!("write: {e}"))
                    })
                    .await
                    {
                        Ok(Ok(())) => Ok(shown),
                        Ok(Err(e)) => Err(e),
                        Err(e) => Err(format!("worker: {e}")),
                    }
                }
                Err(e) => Err(e),
            };
            match result {
                Ok(shown) => finish_file_op(op_id, format!("saved to {shown}")),
                Err(e) => fail_file_op(&state, op_id, "save failed", e),
            }
            ctx.request_repaint();
        });
    });
}

/// Download + (E2EE only) decrypt to a temp path and hand it to the OS
/// opener — every phase, including the opener's own verdict, is a strip
/// row.
fn open_attachment(
    state: &Arc<Mutex<ClientState>>,
    rt: &tokio::runtime::Handle,
    ctx: &egui::Context,
    attachment_id: i64,
    name: String,
    encrypted: bool,
    key_b64: &str,
    nonce_b64: &str,
) {
    let state = Arc::clone(state);
    let ctx = ctx.clone();
    let path = temp_open_path(&name);
    let (key, nonce) = (key_b64.to_string(), nonce_b64.to_string());
    let op_id = push_file_op(&name, FileOpPhase::Downloading);
    rt.spawn(async move {
        let result =
            match materialize(&ctx, op_id, &state, attachment_id, encrypted, &key, &nonce).await {
                Ok(bytes) => {
                    set_file_op_phase(op_id, FileOpPhase::Opening);
                    ctx.request_repaint();
                    match tokio::task::spawn_blocking(move || {
                        std::fs::write(&path, &bytes)
                            .map_err(|e| format!("write: {e}"))
                            .and_then(|()| open_with_os(&path))
                    })
                    .await
                    {
                        Ok(r) => r,
                        Err(e) => Err(format!("worker: {e}")),
                    }
                }
                Err(e) => Err(e),
            };
        match result {
            Ok(()) => finish_file_op(op_id, "opened".into()),
            Err(e) => fail_file_op(&state, op_id, "open failed", e),
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

/// Hand a path to the OS opener and wait just long enough to learn whether
/// it actually took: a missing `xdg-open` or an app that refuses the file
/// is a user-visible failure, not a terminal-only one.
fn open_with_os(path: &std::path::Path) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    let mut cmd = {
        let mut c = std::process::Command::new("open");
        c.arg(path);
        c
    };
    #[cfg(target_os = "windows")]
    let mut cmd = {
        let mut c = std::process::Command::new("cmd");
        c.arg("/C").arg("start").arg("").arg(path);
        c
    };
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    let mut cmd = {
        let mut c = std::process::Command::new("xdg-open");
        c.arg(path);
        c
    };
    let status = cmd
        .status()
        .map_err(|e| format!("OS opener failed to start: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("OS opener exited with {status}"))
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
    clear_upload_cancel(id);
    let mut st = guard(state);
    if let Some(m) = st.main_mut() {
        set_upload_on(m, id, |u| u.phase = UploadPhase::Failed(why));
    }
}

fn drop_upload(state: &Arc<Mutex<ClientState>>, id: u64) {
    clear_upload_cancel(id);
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

// -- Upload cancellation ------------------------------------------------------

/// Flag an in-flight upload as cancelled (the strip's "x" on an active
/// row); the running pipeline notices at its next checkpoint.
fn request_upload_cancel(id: u64) {
    CANCELLED_UPLOADS
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .insert(id);
}

/// Has the user cancelled this upload?
fn upload_cancelled(id: u64) -> bool {
    CANCELLED_UPLOADS
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .contains(&id)
}

/// Terminal-path tidy-up so the flag set never outlives its upload (the
/// three funnels are `fail_upload`, `drop_upload`, and the Done phase).
fn clear_upload_cancel(id: u64) {
    CANCELLED_UPLOADS
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .remove(&id);
}

/// Cancel checkpoint for the send pipeline: when the strip's "x" flagged
/// this upload, consume the flag, pull any optimistic row, and stop
/// tracking the upload. `true` = caller returns without sending anything.
fn upload_stopped(state: &Arc<Mutex<ClientState>>, id: u64, ch: i64, temp: i64) -> bool {
    if !upload_cancelled(id) {
        return false;
    }
    remove_temp(state, ch, temp);
    drop_upload(state, id); // clears the flag too
    true
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

    #[test]
    fn file_op_rows_track_their_lifecycle() {
        // Working → Working → Done/Failed → dropped, addressed by id.
        let id = push_file_op("report.pdf", FileOpPhase::Choosing);
        set_file_op_phase(id, FileOpPhase::Downloading);
        {
            let ops = file_ops();
            let op = ops.iter().find(|o| o.id == id).unwrap();
            assert_eq!(op.status, FileOpStatus::Working(FileOpPhase::Downloading));
        }
        fail_file_op(
            &Arc::new(Mutex::new(ClientState::new())),
            id,
            "open failed",
            "HTTP 404".into(),
        );
        {
            let ops = file_ops();
            let op = ops.iter().find(|o| o.id == id).unwrap();
            assert_eq!(
                op.status,
                FileOpStatus::Failed("open failed: HTTP 404".into())
            );
        }
        finish_file_op(id, "saved to /tmp/x".into());
        {
            let ops = file_ops();
            let op = ops.iter().find(|o| o.id == id).unwrap();
            assert_eq!(op.status, FileOpStatus::Done("saved to /tmp/x".into()));
        }
        drop_file_op(id);
        assert!(file_ops().iter().all(|o| o.id != id));
    }

    #[test]
    fn upload_cancel_flags_round_trip() {
        // An id no real upload can reach, so parallel tests never collide.
        let id = 1 << 62;
        request_upload_cancel(id);
        assert!(upload_cancelled(id));
        clear_upload_cancel(id);
        assert!(!upload_cancelled(id));
    }

    #[test]
    fn random_image_names_are_opaque_webp() {
        let a = random_image_name();
        let b = random_image_name();
        assert_ne!(a, b, "8 random bytes must not repeat");
        for n in [a, b] {
            let hex = n
                .strip_prefix("img_")
                .unwrap()
                .strip_suffix(".webp")
                .unwrap();
            assert_eq!(hex.len(), 16, "16 hex chars: {n}");
            assert!(
                hex.chars()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
                "lowercase hex only: {n}"
            );
        }
    }

    #[test]
    fn pngs_reencode_to_webp_and_non_images_do_not() {
        use image::ImageEncoder;
        let img = image::DynamicImage::ImageRgb8(image::RgbImage::from_pixel(
            4,
            4,
            image::Rgb([200u8, 10, 10]),
        ));
        let mut png = Vec::new();
        image::codecs::png::PngEncoder::new(&mut png)
            .write_image(img.as_bytes(), 4, 4, image::ExtendedColorType::Rgb8)
            .unwrap();
        let webp_bytes = maybe_webp(&png).expect("png qualifies for the image flow");
        // RIFF container header at 0..4, WEBP magic at 8..12 — what the
        // server will validate on POST /attachments/image.
        assert_eq!(&webp_bytes[0..4], b"RIFF");
        assert_eq!(&webp_bytes[8..12], b"WEBP");
        // (WebP may legitimately exceed the PNG for tiny inputs; the
        // contract sends the WebP regardless of relative size.)
        assert!(maybe_webp(b"definitely not an image").is_none());
    }

    #[test]
    fn animated_gifs_keep_the_encrypted_flow_but_single_frames_convert() {
        let frame = |r: u8| {
            image::Frame::new(image::RgbaImage::from_pixel(
                4,
                4,
                image::Rgba([r, 0, 0, 255]),
            ))
        };
        let mut animated = Vec::new();
        image::codecs::gif::GifEncoder::new(&mut animated)
            .encode_frames(vec![frame(40), frame(200)])
            .unwrap();
        assert!(is_animated_gif(&animated));
        assert!(
            maybe_webp(&animated).is_none(),
            "animated gif falls back to the E2EE flow"
        );

        let mut single = Vec::new();
        image::codecs::gif::GifEncoder::new(&mut single)
            .encode_frames(vec![frame(200)])
            .unwrap();
        assert!(!is_animated_gif(&single));
        assert!(maybe_webp(&single).is_some(), "single-frame gif converts");
    }
}
