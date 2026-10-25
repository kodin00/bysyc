//! Shared test harness for the client integration tests.
//!
//! [`Side`] is one fully-connected account — fresh store in a temp dir, a
//! bootstrapped crypto engine, a session token, and the production WS task
//! pushing every server event into [`ClientState`]. Both `tests/e2e.rs` (the
//! live dev-Instance flow) and `tests/hermetic.rs` (the in-process flow
//! against `bysyc_server`) drive real client code paths through this helper,
//! so their assertions line up.
//!
//! `Side::register` takes the base URL and an invite code, so each test
//! supplies its own codes (the e2e test mints them via the server binary; the
//! hermetic test inserts them straight into the DB).

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bysyc_client::crypto::Envelope;
use bysyc_client::net::{Net, publish_keys, spawn_ws};
use bysyc_client::state::{ClientState, ConnStatus, EngineBoot, MainState, Phase, guard};
use bysyc_client::store::{Store, bootstrap_engine};
use bysyc_client::views;
use bysyc_common::protocol::{MessageDto, RegisterRequest};
use eframe::egui::Context as EguiContext;

/// How long to wait for a WS-driven condition before failing.
pub const WAIT_SECS: u64 = 20;

// ---------------------------------------------------------------------------
// TempDir
// ---------------------------------------------------------------------------

/// Directory removed recursively on drop — each side's store lives in one,
/// so reruns never touch a real database.
pub struct TempDir(pub PathBuf);

impl TempDir {
    pub fn new(tag: &str) -> TempDir {
        let path = std::env::temp_dir().join(format!(
            "bysyc-test-{}-{tag}-{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        std::fs::create_dir_all(&path).expect("create temp dir");
        TempDir(path)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// ---------------------------------------------------------------------------
// Side
// ---------------------------------------------------------------------------

/// One fully-connected account: fresh store in a temp dir, bootstrapped
/// engine (real OS-keychain passphrase), session token, and the production
/// WS task pushing every server event into `state`.
pub struct Side {
    pub username: String,
    pub account_id: i64,
    pub base: String,
    pub token: String,
    pub state: Arc<Mutex<ClientState>>,
    pub store: Arc<Mutex<Store>>,
    pub net: Net,
    pub ws_task: tokio::task::JoinHandle<()>,
    _dir: TempDir,
}

impl Side {
    /// Register a fresh account and connect its WS gateway. Mirrors the
    /// login flow in `app.rs`/`views/login.rs`: engine bootstrapped and
    /// staged in `pending_engine` BEFORE the first `Ready` (so the mailbox
    /// batch can decrypt immediately), keys published right after register.
    pub async fn register(
        rt: &tokio::runtime::Handle,
        ctx: &EguiContext,
        base: &str,
        username: &str,
        password: &str,
        invite_code: &str,
    ) -> Side {
        let dir = TempDir::new(username);
        let store = Arc::new(Mutex::new(
            Store::open(&dir.path().join("bysyc.db")).expect("open temp store"),
        ));
        // Real keychain-backed passphrase, keyed by the random username.
        let (engine, outbound) = bootstrap_engine(&store, username).expect("bootstrap engine");

        let resp = Net::new(base)
            .register(&RegisterRequest {
                username: username.to_string(),
                password: password.to_string(),
                invite_code: invite_code.to_string(),
                identity_key: engine.identity_key(),
            })
            .await
            .unwrap_or_else(|e| panic!("register {username}: {e}"));
        let net = Net::authenticated(base, &resp.token);
        publish_keys(&net, &engine).await;

        let state = Arc::new(Mutex::new(ClientState::new()));
        {
            let mut st = guard(&state);
            st.pending_engine = Some(EngineBoot {
                engine: engine.clone(),
                outbound,
            });
            // run_ws exits immediately while Disconnected — the login flow
            // flips the phase to Connecting before spawning it.
            st.phase = Phase::Connecting("test".into());
        }
        let ws_task = spawn_ws(
            rt,
            Arc::clone(&state),
            Arc::clone(&store),
            ctx.clone(),
            base.to_string(),
            resp.token.clone(),
        );
        let side = Side {
            username: username.to_string(),
            account_id: resp.account.id,
            base: base.to_string(),
            token: resp.token,
            state,
            store,
            net,
            ws_task,
            _dir: dir,
        };
        side.wait_until(
            "first WS Ready",
            || side.is_logged_in(),
            || format!("{} never reached LoggedIn", side.username),
        )
        .await;
        assert!(
            side.engine().is_some(),
            "engine must be attached after Ready"
        );
        side
    }

    pub fn is_logged_in(&self) -> bool {
        guard(&self.state).is_logged_in()
    }

    pub fn engine(&self) -> Option<Arc<bysyc_client::crypto::Engine>> {
        guard(&self.state).main().and_then(|m| m.engine.clone())
    }

    /// Run a read-only query against this side's live world.
    pub fn with_main<T>(&self, f: impl FnOnce(&MainState) -> T) -> Option<T> {
        guard(&self.state).main().map(f)
    }

    /// `true` when `id` is in the online set (Ready + Presence events).
    pub fn sees_online(&self, id: i64) -> bool {
        self.with_main(|m| m.online.contains(&id)).unwrap_or(false)
    }

    /// Send chat text through the REAL send path — the same
    /// `encrypt_share_and_send` the composer uses (Megolm encrypt, share
    /// first when needed, POST, persist own plaintext, reconcile temp row).
    pub async fn send_chat(&self, channel_id: i64, text: &str) -> MessageDto {
        let engine = self
            .engine()
            .expect("crypto engine attached (sending is impossible without it)");
        let envelope = Envelope::Chat {
            text: text.to_string(),
            reply_to: None,
        };
        views::attachments::encrypt_share_and_send(
            &self.state,
            &self.store,
            &self.net,
            &engine,
            channel_id,
            &envelope,
            -1,
            None,
        )
        .await
        .unwrap_or_else(|e| panic!("{}: send_chat on {channel_id} failed: {e}", self.username))
    }

    /// Drop the socket (the server fans out `Presence{false}` to friends)
    /// and retire the WS task. Pair with [`Side::respawn_ws`]. Mirrors what
    /// the WS loop does on connection loss: status flips to Reconnecting.
    pub fn drop_ws(&mut self) {
        self.ws_task.abort();
        let mut st = guard(&self.state);
        st.ws_generation += 1;
        if let Some(m) = st.main_mut() {
            m.connection = ConnStatus::Reconnecting("test: socket dropped".into());
        }
    }

    /// `true` once a socket is live again (Ready applied → Online).
    pub fn connection_online(&self) -> bool {
        self.with_main(|m| matches!(m.connection, ConnStatus::Online))
            .unwrap_or(false)
    }

    /// Open a fresh socket exactly like a reconnect: the bumped generation
    /// owns a new `run_ws` loop (phase stays LoggedIn, so `Ready` takes the
    /// reconnect path — server world replaced, local caches kept).
    pub fn respawn_ws(&mut self, rt: &tokio::runtime::Handle, ctx: &EguiContext) {
        self.ws_task = spawn_ws(
            rt,
            Arc::clone(&self.state),
            Arc::clone(&self.store),
            ctx.clone(),
            self.base.clone(),
            self.token.clone(),
        );
    }

    /// Best-effort teardown: stop the gateway, invalidate the session,
    /// remove the account's secrets-file entries. Temp dir goes away via Drop.
    pub async fn shutdown(self) {
        self.ws_task.abort();
        let _ = self.net.logout().await;
        bysyc_client::store::secret_delete_profile(&self.username);
    }

    /// Poll `cond` every 100 ms up to [`WAIT_SECS`]; on timeout fail with
    /// `what` diverged plus `diag` (recomputed at the deadline).
    pub async fn wait_until(
        &self,
        what: &str,
        mut cond: impl FnMut() -> bool,
        diag: impl Fn() -> String,
    ) {
        let deadline = Instant::now() + Duration::from_secs(WAIT_SECS);
        loop {
            if cond() {
                return;
            }
            if Instant::now() > deadline {
                panic!(
                    "test: timed out after {WAIT_SECS}s waiting for {what} — {}",
                    diag()
                );
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Wait until this side's store holds `expected` as the decrypted
    /// plaintext of `msg_id`. The write only happens inside
    /// `apply_server_msg` (WS receive path), so success proves the whole
    /// wire → WS → state → Megolm-decrypt → store chain.
    pub async fn wait_for_plaintext(
        &self,
        msg_id: i64,
        channel_id: i64,
        expected: &str,
        what: &str,
    ) {
        self.wait_until(
            what,
            || {
                guard(&self.store)
                    .plaintext(msg_id)
                    .is_some_and(|p| p == expected)
            },
            || self.plaintext_diag(msg_id, channel_id, expected),
        )
        .await;
    }

    /// Failure detail for a message that never decrypted: everything the
    /// receiver holds for that channel, plus world-state context.
    fn plaintext_diag(&self, msg_id: i64, channel_id: i64, expected: &str) -> String {
        let mut out = format!(
            "{} never decrypted message {msg_id} (expected {expected:?}) in channel {channel_id}\n",
            self.username
        );
        {
            let s = guard(&self.store);
            for m in s.messages_for(channel_id, None, 50) {
                out.push_str(&format!(
                    "  store: id={} sender={} plaintext={:?} content={:?}\n",
                    m.id,
                    m.sender_id,
                    s.plaintext(m.id),
                    if m.content.len() > 40 {
                        format!("{}…", &m.content[..40])
                    } else {
                        m.content.clone()
                    }
                ));
            }
        }
        self.with_main(|m| {
            out.push_str(&format!(
                "  state: cached_msgs={} mailbox={} identities={} online={:?} notice={:?}\n",
                m.messages.get(&channel_id).map(|v| v.len()).unwrap_or(0),
                m.mailbox.len(),
                m.identities.len(),
                m.online,
                m.notice
            ));
        });
        out
    }
}

// ---------------------------------------------------------------------------
// .env parsing (live e2e only)
// ---------------------------------------------------------------------------

/// Minimal `.env` parser: `KEY=VALUE` lines, comments/blank lines skipped.
/// Used by the live e2e test's `make-invite` spawn (the hermetic test mints
/// codes straight into the DB and never reads `.env`).
#[allow(dead_code)] // only the e2e binary consumes this; hermetic does not
pub fn dotenv_vars(path: &Path) -> Vec<(String, String)> {
    let text =
        std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    text.lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| {
            let (k, v) = l.split_once('=')?;
            Some((k.trim().to_string(), v.trim().to_string()))
        })
        .collect()
}
