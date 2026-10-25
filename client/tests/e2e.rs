//! Headless two-account end-to-end test of the REAL client stack —
//! `net.rs` (REST + the actual `run_ws` gateway loop), `state.rs`
//! (`apply_server_msg`), `store.rs` (SQLite + keychain engine bootstrap)
//! and the crypto engine (Olm/Megolm) — against a live bysyc Instance.
//!
//! Everything below runs the production code paths: `spawn_ws` starts the
//! genuine WS task (so both sides receive and apply server pushes), and
//! sends go through `views::attachments::encrypt_share_and_send` — the one
//! function the chat composer itself uses. The only UI-side glue the test
//! replicates is the three lines of state bookkeeping the views do after a
//! REST call (pushing an opened DM / created guild into the world), because
//! that lives inside egui closures.
//!
//! Run (needs the dev Instance on :8080 and the compose infra up):
//!
//! ```text
//! mise run test-e2e
//! # or directly:
//! BYSYC_E2E=1 cargo test -p bysyc-client --test e2e -- --ignored --nocapture
//! ```
//!
//! Gated twice: `#[ignore]` keeps plain `cargo test` hermetic, and the
//! `BYSYC_E2E=1` env gate makes a bare `--ignored` run a silent no-op.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bysyc_client::crypto::Envelope;
use bysyc_client::net::{Net, publish_keys, spawn_ws};
use bysyc_client::state::{ClientState, ConnStatus, EngineBoot, MainState, Phase, guard};
use bysyc_client::store::{Store, bootstrap_engine};
use bysyc_client::views;
use bysyc_common::protocol::{
    ChannelKind, CreateGuildInviteRequest, CreateGuildRequest, FriendList, JoinGuildRequest,
    MessageDto, OpenDmRequest, RegisterRequest,
};
use eframe::egui::Context as EguiContext;

/// How long to wait for a WS-driven condition before failing.
const WAIT_SECS: u64 = 20;

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

/// Directory removed recursively on drop — each side's store lives in one,
/// so reruns never touch a real database.
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> TempDir {
        let path = std::env::temp_dir().join(format!(
            "bysyc-e2e-{}-{tag}-{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        std::fs::create_dir_all(&path).expect("create temp dir");
        TempDir(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// One fully-connected account: fresh store in a temp dir, bootstrapped
/// engine (real OS-keychain passphrase), session token, and the production
/// WS task pushing every server event into `state`.
struct Side {
    username: String,
    account_id: i64,
    base: String,
    token: String,
    state: Arc<Mutex<ClientState>>,
    store: Arc<Mutex<Store>>,
    net: Net,
    ws_task: tokio::task::JoinHandle<()>,
    _dir: TempDir,
}

impl Side {
    /// Register a fresh account and connect its WS gateway. Mirrors the
    /// login flow in `app.rs`/`views/login.rs`: engine bootstrapped and
    /// staged in `pending_engine` BEFORE the first `Ready` (so the mailbox
    /// batch can decrypt immediately), keys published right after register.
    async fn register(
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
            st.phase = Phase::Connecting("e2e".into());
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

    fn is_logged_in(&self) -> bool {
        guard(&self.state).is_logged_in()
    }

    fn engine(&self) -> Option<Arc<bysyc_client::crypto::Engine>> {
        guard(&self.state).main().and_then(|m| m.engine.clone())
    }

    /// Run a read-only query against this side's live world.
    fn with_main<T>(&self, f: impl FnOnce(&MainState) -> T) -> Option<T> {
        guard(&self.state).main().map(f)
    }

    /// `true` when `id` is in the online set (Ready + Presence events).
    fn sees_online(&self, id: i64) -> bool {
        self.with_main(|m| m.online.contains(&id)).unwrap_or(false)
    }

    /// Send chat text through the REAL send path — the same
    /// `encrypt_share_and_send` the composer uses (Megolm encrypt, share
    /// first when needed, POST, persist own plaintext, reconcile temp row).
    async fn send_chat(&self, channel_id: i64, text: &str) -> MessageDto {
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
    fn drop_ws(&mut self) {
        self.ws_task.abort();
        let mut st = guard(&self.state);
        st.ws_generation += 1;
        if let Some(m) = st.main_mut() {
            m.connection = ConnStatus::Reconnecting("e2e: socket dropped".into());
        }
    }

    /// `true` once a socket is live again (Ready applied → Online).
    fn connection_online(&self) -> bool {
        self.with_main(|m| matches!(m.connection, ConnStatus::Online))
            .unwrap_or(false)
    }

    /// Open a fresh socket exactly like a reconnect: the bumped generation
    /// owns a new `run_ws` loop (phase stays LoggedIn, so `Ready` takes the
    /// reconnect path — server world replaced, local caches kept).
    fn respawn_ws(&mut self, rt: &tokio::runtime::Handle, ctx: &EguiContext) {
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
    async fn shutdown(self) {
        self.ws_task.abort();
        let _ = self.net.logout().await;
        bysyc_client::store::secret_delete_profile(&self.username);
    }

    /// Poll `cond` every 100 ms up to [`WAIT_SECS`]; on timeout fail with
    /// `what` diverged plus `diag` (recomputed at the deadline).
    async fn wait_until(
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
                    "e2e: timed out after {WAIT_SECS}s waiting for {what} — {}",
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
    async fn wait_for_plaintext(&self, msg_id: i64, channel_id: i64, expected: &str, what: &str) {
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
// Invite minting
// ---------------------------------------------------------------------------

/// Mint a registration invite by running the prebuilt server binary
/// (`target/debug/bysyc-server make-invite`) with the repo `.env` loaded —
/// the same thing `mise run dev-server` runs. Using the binary (not
/// `cargo run`) matters: an inner cargo would block on the target-dir lock
/// the outer `cargo test` already holds.
fn mint_invite() -> String {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("client/ has a parent")
        .to_path_buf();
    let bin = root.join("target/debug/bysyc-server");
    assert!(
        bin.exists(),
        "prebuilt server binary missing at {} — start the dev Instance (mise run dev-server) \
         or set INVITE_A/INVITE_B",
        bin.display()
    );
    let out = std::process::Command::new(&bin)
        .arg("make-invite")
        .envs(dotenv_vars(&root.join(".env")))
        .output()
        .expect("spawn make-invite");
    assert!(
        out.status.success(),
        "make-invite failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let code = String::from_utf8_lossy(&out.stdout).trim().to_string();
    assert!(
        code.len() == 22 && code.chars().all(|c| c.is_ascii_alphanumeric()),
        "unexpected make-invite output: {code:?}"
    );
    code
}

/// Minimal `.env` parser: `KEY=VALUE` lines, comments/blank lines skipped.
fn dotenv_vars(path: &Path) -> Vec<(String, String)> {
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

// ---------------------------------------------------------------------------
// The test
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "live e2e against the dev Instance — run with `mise run test-e2e`"]
async fn two_accounts_full_flow() {
    if std::env::var("BYSYC_E2E").ok().as_deref() != Some("1") {
        return; // silent no-op unless explicitly opted in
    }

    let base = std::env::var("BYSYC_E2E_BASE").unwrap_or_else(|_| "http://127.0.0.1:8080".into());
    let rt = tokio::runtime::Handle::current();
    // Headless egui context: request_repaint is a no-op without a window;
    // everything else (apply_server_msg) is UI-free.
    let ctx = EguiContext::default();

    // 1. Fresh identities: random suffixes keep reruns clean (usernames are
    //    unique, and the keychain passphrase is keyed per-username).
    let suffix = rand::random::<u32>();
    let invite_a = std::env::var("INVITE_A").unwrap_or_else(|_| mint_invite());
    let invite_b = std::env::var("INVITE_B").unwrap_or_else(|_| mint_invite());
    let name_a = format!("e2e_a_{suffix}");
    let name_b = format!("e2e_b_{suffix}");
    let password = format!("e2e-pass-{suffix}");
    println!("e2e: accounts {name_a} / {name_b} against {base}");

    let mut a = Side::register(&rt, &ctx, &base, &name_a, &password, &invite_a).await;
    let b = Side::register(&rt, &ctx, &base, &name_b, &password, &invite_b).await;
    let (a_id, b_id) = (a.account_id, b.account_id);
    println!("e2e: both registered and Ready (a={a_id}, b={b_id})");

    // 2. Friendship: a requests (REST), b must get FriendRequested over WS.
    a.net
        .send_friend_request(b_id)
        .await
        .expect("friend request");
    b.wait_until(
        "b receives FriendRequested via WS",
        || {
            b.with_main(|m| m.incoming_requests.iter().any(|x| x.id == a_id))
                .unwrap_or(false)
        },
        || {
            format!(
                "b's incoming_requests never contained a: {:?}",
                b.with_main(|m| m.incoming_requests.clone())
            )
        },
    )
    .await;
    println!("e2e: FriendRequested delivered to b over WS");

    // b accepts; a must see the acceptance over WS (FriendRequestAccepted).
    b.net.accept_friend_request(a_id).await.expect("accept");
    a.wait_until(
        "a receives FriendRequestAccepted via WS",
        || {
            a.with_main(|m| m.friends.iter().any(|x| x.id == b_id))
                .unwrap_or(false)
        },
        || {
            format!(
                "a's friends never contained b: {:?}",
                a.with_main(|m| m.friends.clone())
            )
        },
    )
    .await;
    // Both sides see each other as friends (a via the WS event, b via REST).
    let FriendList {
        friends: b_friends, ..
    } = b.net.friends().await.expect("b /friends");
    assert!(
        b_friends.iter().any(|x| x.id == a_id),
        "b's friend list is missing a ({a_id}): {b_friends:?}"
    );
    println!("e2e: a and b are friends on both sides");

    // 3. Presence over WS. Both sockets opened BEFORE the friendship
    //    existed, so b has never seen a online — reconnect a now that they
    //    are friends: the server fans out Presence{true} to friends before
    //    it queues Ready, so waiting for a's own Ready orders things. The
    //    1.5 s pause after the abort lets the server retire the old socket
    //    first (otherwise its offline fan-out could land after the new
    //    socket's online one).
    a.drop_ws();
    tokio::time::sleep(Duration::from_millis(1500)).await;
    a.respawn_ws(&rt, &ctx);
    a.wait_until(
        "a's reconnected socket reaches Ready",
        || a.connection_online(),
        || format!("{} never got Ready after respawn", name_a),
    )
    .await;
    b.wait_until(
        "b sees a online (Presence event)",
        || b.sees_online(a_id),
        || {
            format!(
                "b never saw {} online after reconnect (online={:?})",
                name_a,
                b.with_main(|m| m.online.clone()).unwrap_or_default()
            )
        },
    )
    .await;
    // And the offline edge: drop again, b must observe Presence{false}.
    a.drop_ws();
    b.wait_until(
        "b sees a go offline (Presence offline fan-out)",
        || !b.sees_online(a_id),
        || {
            format!(
                "b still saw {} online after the socket dropped (online={:?})",
                name_a,
                b.with_main(|m| m.online.clone()).unwrap_or_default()
            )
        },
    )
    .await;
    // a must be connected for the rest of the flow: bring it back.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    a.respawn_ws(&rt, &ctx);
    a.wait_until(
        "a's second reconnect reaches Ready",
        || a.connection_online(),
        || format!("{} never got Ready after the second respawn", name_a),
    )
    .await;
    println!("e2e: b observed a's online AND offline presence edges over WS");

    // 4. DM, both directions. a opens the DM; the UI pushes it into the
    //    world (the one view-side step replicated here — it lives in an
    //    egui closure in open_dm_and_select).
    let dm = a
        .net
        .open_dm(&OpenDmRequest { account_id: b_id })
        .await
        .expect("open DM");
    let dm_ch = dm.channel.id;
    {
        let mut st = guard(&a.state);
        if let Some(m) = st.main_mut()
            && !m.dms.iter().any(|d| d.channel.id == dm_ch)
        {
            m.dms.push(dm.clone());
        }
    }
    println!("e2e: DM channel {dm_ch} open");

    // b discovers the DM the way the UI does when its user clicks the friend
    // (idempotent open_dm from the other side) — BEFORE a sends anything,
    // because live delivery on a fresh channel requires the gateway-side
    // subscription sync that follows a client Heartbeat (gateway contract:
    // "a client that just opened a DM should send a Heartbeat"). Both sides
    // nudge exactly like open_dm_and_select / spawn_guild_rest do.
    let dm_b = b
        .net
        .open_dm(&OpenDmRequest { account_id: a_id })
        .await
        .expect("b open DM");
    assert_eq!(dm_b.channel.id, dm_ch, "open_dm must be idempotent");
    {
        let mut st = guard(&b.state);
        if let Some(m) = st.main_mut() {
            if !m.dms.iter().any(|d| d.channel.id == dm_ch) {
                m.dms.push(dm_b.clone());
            }
            if let Some(h) = m.net.as_ref() {
                h.heartbeat();
            }
        }
    }
    {
        let mut st = guard(&a.state);
        if let Some(m) = st.main_mut()
            && let Some(h) = m.net.as_ref()
        {
            h.heartbeat();
        }
    }
    // Let the gateway apply the new chan:{dm_ch} subscriptions before any
    // publish (the heartbeat rides the WS while the send is HTTP — no
    // cross-transport ordering).
    tokio::time::sleep(Duration::from_millis(500)).await;

    // a → b through the real send path (first send: Megolm session created,
    // key shared to b over Olm via the mailbox, message POSTed).
    let text1 = "hello e2ee";
    let dto1 = a.send_chat(dm_ch, text1).await;
    // The wire never saw the plaintext.
    assert_ne!(dto1.content, text1, "message content must be ciphertext");
    b.wait_for_plaintext(dto1.id, dm_ch, text1, "b decrypts a's first DM")
        .await;
    let cached = b
        .with_main(|m| {
            m.messages
                .get(&dm_ch)
                .map(|v| v.iter().any(|x| x.id == dto1.id))
                .unwrap_or(false)
        })
        .unwrap_or(false);
    assert!(
        cached,
        "b's live message cache must hold message {}",
        dto1.id
    );
    println!("e2e: b decrypted a's first DM ({})", dto1.id);

    // b → a: b replies through the same real path. Proves the reverse
    // direction AND b's OTK bootstrap (b's first outbound Megolm session is
    // shared to a over Olm).
    let text2 = "hi from b";
    let dto2 = b.send_chat(dm_ch, text2).await;
    a.wait_for_plaintext(dto2.id, dm_ch, text2, "a decrypts b's reply")
        .await;
    println!("e2e: a decrypted b's reply ({})", dto2.id);

    // 5. Session reuse: a's second message rides the SAME outbound Megolm
    //    session — same session id, no re-share, no rotation.
    let sid_after_first = a
        .with_main(|m| m.outbound_sid.get(&dm_ch).cloned())
        .flatten()
        .expect("a must track the DM session id after the first send");
    let text3 = "hello again";
    let dto3 = a.send_chat(dm_ch, text3).await;
    let sid_after_third = a
        .with_main(|m| m.outbound_sid.get(&dm_ch).cloned())
        .flatten()
        .expect("a must still track the DM session id");
    assert_eq!(
        sid_after_first, sid_after_third,
        "the DM session must not rotate between sends"
    );
    assert!(
        a.engine()
            .expect("a engine")
            .drain_pending_shares()
            .is_empty(),
        "no share may be pending after a reuse send"
    );
    b.wait_for_plaintext(
        dto3.id,
        dm_ch,
        text3,
        "b decrypts a's second DM (session reuse)",
    )
    .await;
    println!(
        "e2e: session reuse proven (sid unchanged, {} decrypted)",
        dto3.id
    );

    // 6. Guild: b creates one (default #general text channel), invites a,
    //    a joins by code. b's MemberJoined widens the share roster; a gets
    //    GuildJoined over WS.
    let guild = b
        .net
        .create_guild(&CreateGuildRequest {
            name: format!("e2e_g_{suffix}"),
        })
        .await
        .expect("create guild");
    let guild_id = guild.id;
    {
        // View-side bookkeeping (spawn_guild_rest pushes the REST result).
        let mut st = guard(&b.state);
        if let Some(m) = st.main_mut()
            && !m.guilds.iter().any(|g| g.id == guild_id)
        {
            m.guilds.push(guild.clone());
        }
    }
    let text_channel = guild
        .channels
        .iter()
        .find(|c| c.kind == ChannelKind::Text)
        .expect("guild has a default text channel");
    let invite = b
        .net
        .create_guild_invite(
            guild_id,
            &CreateGuildInviteRequest {
                max_uses: Some(1),
                ttl_secs: None,
            },
        )
        .await
        .expect("create guild invite");
    a.net
        .join_guild(&JoinGuildRequest { code: invite.code })
        .await
        .expect("join guild");
    {
        // spawn_guild_rest heartbeats after a successful join (new channels
        // → gateway subscription sync); replicate that here.
        let mut st = guard(&a.state);
        if let Some(m) = st.main_mut()
            && let Some(h) = m.net.as_ref()
        {
            h.heartbeat();
        }
    }
    a.wait_until(
        "a receives GuildJoined via WS",
        || {
            a.with_main(|m| m.guilds.iter().any(|g| g.id == guild_id))
                .unwrap_or(false)
        },
        || format!("a's guilds never contained {guild_id}"),
    )
    .await;
    b.wait_until(
        "b sees MemberJoined(a) via WS",
        || {
            b.with_main(|m| {
                m.guild_members
                    .get(&guild_id)
                    .is_some_and(|roster| roster.contains(&a_id))
            })
            .unwrap_or(false)
        },
        || format!("b's roster for {guild_id} never contained a"),
    )
    .await;
    println!("e2e: a joined guild {guild_id}, b saw MemberJoined");

    // b's first guild message: new Megolm session shared over the mailbox
    // to the newcomer a, who must decrypt it.
    let text4 = format!("guild hello {suffix}");
    let dto4 = b.send_chat(text_channel.id, &text4).await;
    a.wait_for_plaintext(
        dto4.id,
        text_channel.id,
        &text4,
        "a decrypts b's guild message",
    )
    .await;
    println!("e2e: a decrypted the guild-channel message ({})", dto4.id);

    // 7. Cleanup: sessions invalidated, keychain entries and temp dirs gone.
    a.shutdown().await;
    b.shutdown().await;
    println!(
        "e2e: FULL FLOW GREEN — friends, presence, DM E2EE both ways, session reuse, guild share to newcomer"
    );
}
