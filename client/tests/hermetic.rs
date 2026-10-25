//! Hermetic two-account integration test: spins the bysyc-server router up
//! IN-PROCESS (no separate binary), backed by containerized postgres +
//! redis, then drives the real client stack (`net.rs`, `state.rs`,
//! `store.rs`, the Olm/Megolm engine) through [`common::Side`] against the
//! ephemeral port axum is bound to.
//!
//! Runs by default — NOT `#[ignore]`, NOT `BYSYC_E2E`-gated. Needs Docker
//! for the postgres/redis containers. If Docker is unavailable, `cargo test
//! -p bysyc-client` still runs every other (unit) test; this one fails to
//! acquire its containers and is skipped by filtering `--skip hermetic`.
//!
//! S3: the chat text path (`Envelope::Chat`) never touches S3, and
//! `bysyc_server::boot` constructs the S3 client lazily (no connection at
//! boot), so no localstack/minio container is started — `S3_ENDPOINT` points
//! at a placeholder that is never contacted.

mod common;

use std::time::Duration;

use bysyc_common::protocol::{
    ChannelKind, CreateGuildInviteRequest, CreateGuildRequest, FriendList, JoinGuildRequest,
    OpenDmRequest,
};
use bysyc_server::{Config, boot, router, ws};
use eframe::egui::Context as EguiContext;
use rand::distr::{Alphanumeric, SampleString};
use testcontainers::runners::AsyncRunner;
use testcontainers_modules::{postgres, redis};

use common::Side;

/// A fresh 22-char alphanumeric registration code, matching the format the
/// server's own `make_invite` mints (so the `registration_invites` row and
/// the auth register flow accept it verbatim).
fn invite_code() -> String {
    Alphanumeric.sample_string(&mut rand::rng(), 22)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_accounts_full_flow_hermetic() {
    // ---- 1. Containers: postgres:16 + redis:7 -------------------------------
    let pg_container = postgres::Postgres::default()
        .start()
        .await
        .expect("start postgres container");
    let redis_container = redis::Redis::default()
        .start()
        .await
        .expect("start redis container");
    let pg_host = pg_container.get_host().await.expect("pg host");
    let pg_port = pg_container
        .get_host_port_ipv4(5432)
        .await
        .expect("pg port");
    let rd_host = redis_container.get_host().await.expect("redis host");
    let rd_port = redis_container
        .get_host_port_ipv4(6379)
        .await
        .expect("redis port");
    let database_url = format!("postgres://postgres:postgres@{pg_host}:{pg_port}/postgres");
    let redis_url = format!("redis://{rd_host}:{rd_port}/1");

    // ---- 2. In-process server: boot, event bus, router, axum::serve --------
    // S3 endpoint is a placeholder; the chat text path never reaches it.
    let config = Config {
        database_url: database_url.clone(),
        redis_url: redis_url.clone(),
        s3_endpoint: "http://127.0.0.1:8333".into(),
        s3_access_key: "bysyc".into(),
        s3_secret_key: "bysyc".into(),
        s3_bucket: "bysyc".into(),
        turn_addr: "localhost:3478".into(),
        turn_user: "bysyc".into(),
        turn_password: "bysyc".into(),
        attachment_max_bytes: 50 * 1024 * 1024,
        db_max_connections: 4,
    };
    let state = boot(&config).await.expect("boot in-process server");
    ws::start_event_bus(&redis_url, 2);
    let app = router(state.clone());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral");
    let addr = listener.local_addr().expect("listener addr");
    let server_task = tokio::spawn(async move {
        // into_make_service_with_connect_info injects the peer SocketAddr so
        // the auth rate-limiter keys on the real client IP (matches main.rs).
        let serve = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        );
        if let Err(e) = serve.await {
            eprintln!("hermetic: axum::serve exited: {e}");
        }
    });
    let base = format!("http://{addr}");

    // ---- 3. Mint two registration invites straight into the DB ------------
    // The first Side to register becomes the Instance admin (first-registrant
    // flow). Both codes are valid `registration_invites` rows.
    let invite_a = invite_code();
    let invite_b = invite_code();
    sqlx::query("INSERT INTO registration_invites(code) VALUES ($1)")
        .bind(&invite_a)
        .execute(&state.pg)
        .await
        .expect("insert invite A");
    sqlx::query("INSERT INTO registration_invites(code) VALUES ($1)")
        .bind(&invite_b)
        .execute(&state.pg)
        .await
        .expect("insert invite B");

    // ---- 4. The flow: mirrors tests/e2e.rs::two_accounts_full_flow ---------
    let rt = tokio::runtime::Handle::current();
    let ctx = EguiContext::default();

    let suffix = rand::random::<u32>();
    let name_a = format!("herm_a_{suffix}");
    let name_b = format!("herm_b_{suffix}");
    let password = format!("herm-pass-{suffix}");
    println!("hermetic: accounts {name_a} / {name_b} against {base}");

    let mut a = Side::register(&rt, &ctx, &base, &name_a, &password, &invite_a).await;
    let b = Side::register(&rt, &ctx, &base, &name_b, &password, &invite_b).await;
    let (a_id, b_id) = (a.account_id, b.account_id);
    println!("hermetic: both registered and Ready (a={a_id}, b={b_id})");

    // Friendship: a requests, b gets FriendRequested over WS, b accepts, a
    // sees FriendRequestAccepted over WS.
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
    let FriendList {
        friends: b_friends, ..
    } = b.net.friends().await.expect("b /friends");
    assert!(
        b_friends.iter().any(|x| x.id == a_id),
        "b's friend list is missing a ({a_id}): {b_friends:?}"
    );

    // Presence edges: reconnect a (friendship now exists) so the server fans
    // out Presence{true}; then drop again to observe Presence{false}.
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
        "b sees a online",
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
    a.drop_ws();
    b.wait_until(
        "b sees a go offline",
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
    tokio::time::sleep(Duration::from_millis(1500)).await;
    a.respawn_ws(&rt, &ctx);
    a.wait_until(
        "a's second reconnect reaches Ready",
        || a.connection_online(),
        || format!("{} never got Ready after the second respawn", name_a),
    )
    .await;

    // DM, both directions. a opens it; the UI-side push into the world is
    // replicated here (it lives in an egui closure in the real app).
    let dm = a
        .net
        .open_dm(&OpenDmRequest { account_id: b_id })
        .await
        .expect("open DM");
    let dm_ch = dm.channel.id;
    {
        let mut st = bysyc_client::state::guard(&a.state);
        if let Some(m) = st.main_mut()
            && !m.dms.iter().any(|d| d.channel.id == dm_ch)
        {
            m.dms.push(dm.clone());
        }
    }
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
    tokio::time::sleep(Duration::from_millis(500)).await;

    // a → b through the real send path: Megolm session created, key shared
    // to b over Olm via the mailbox, message POSTed.
    let text1 = "hello herm";
    let dto1 = a.send_chat(dm_ch, text1).await;
    assert_ne!(dto1.content, text1, "message content must be ciphertext");
    b.wait_for_plaintext(dto1.id, dm_ch, text1, "b decrypts a's first DM")
        .await;
    assert!(
        b.with_main(|m| {
            m.messages
                .get(&dm_ch)
                .map(|v| v.iter().any(|x| x.id == dto1.id))
                .unwrap_or(false)
        })
        .unwrap_or(false),
        "b's live message cache must hold message {}",
        dto1.id
    );

    // b → a: b's first outbound Megolm session is shared to a over Olm.
    let text2 = "hi from b";
    let dto2 = b.send_chat(dm_ch, text2).await;
    a.wait_for_plaintext(dto2.id, dm_ch, text2, "a decrypts b's reply")
        .await;

    // Session reuse: a's second send rides the same outbound Megolm session
    // — same session id, no re-share, no rotation.
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

    // Guild: b creates one (default text channel), invites a, a joins by
    // code. b's MemberJoined widens the share roster; a gets GuildJoined.
    let guild = b
        .net
        .create_guild(&CreateGuildRequest {
            name: format!("herm_g_{suffix}"),
        })
        .await
        .expect("create guild");
    let guild_id = guild.id;
    {
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

    // b's first guild message: new Megolm session shared over the mailbox to
    // the newcomer a, who must decrypt it.
    let text4 = format!("guild hello {suffix}");
    let dto4 = b.send_chat(text_channel.id, &text4).await;
    a.wait_for_plaintext(
        dto4.id,
        text_channel.id,
        &text4,
        "a decrypts b's guild message",
    )
    .await;

    // ---- 5. Teardown -------------------------------------------------------
    a.shutdown().await;
    b.shutdown().await;
    server_task.abort();
    drop(state);
    drop(pg_container);
    drop(redis_container);
    println!(
        "hermetic: FULL FLOW GREEN — friends, presence, DM E2EE both ways, \
         session reuse, guild share to newcomer"
    );
}
