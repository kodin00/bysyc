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

mod common;

use std::path::Path;
use std::time::Duration;

use bysyc_common::protocol::{
    ChannelKind, CreateGuildInviteRequest, CreateGuildRequest, FriendList, JoinGuildRequest,
    OpenDmRequest,
};
use eframe::egui::Context as EguiContext;

use common::{Side, dotenv_vars};

// ---------------------------------------------------------------------------
// Invite minting (live Instance only)
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
    // Inline the view-side bookkeeping (the helper closure lives in egui in
    // the real app): push the DM channel into the world if absent.
    {
        let mut st = bysyc_client::state::guard(&a.state);
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
        let mut st = bysyc_client::state::guard(&b.state);
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
        let mut st = bysyc_client::state::guard(&a.state);
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
        let mut st = bysyc_client::state::guard(&b.state);
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
        let mut st = bysyc_client::state::guard(&a.state);
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
