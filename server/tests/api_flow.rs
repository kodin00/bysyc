//! B1: REST surface — auth, invite gating + admin mint, guild lifecycle,
//! message send/page/delete, attachment create/download (with the Tier-1
//! IDOR fix assertion), and the friend graph.
//!
//! Each test boots its own server (own port, own per-IP auth rate limiter
//! budget) against the shared backing services. Unique usernames keep
//! concurrent tests isolated: every account/guild/channel gets a distinct
//! auto-increment id, so derived Redis topics never collide.

mod common;

use std::time::Duration;

use bysyc_common::protocol::{
    AccountInfo, ApiError, ChannelKind, CreateAttachmentRequest, CreateAttachmentResponse,
    CreateGuildInviteRequest, CreateGuildRequest, DownloadUrlResponse, DmChannel, ErrorCode,
    FriendList, GuildInfo, GuildInviteDto, JoinGuildRequest, MessageDto, MessageKind, MessagePage,
    OpenDmRequest, SendMessageRequest,
};
use common::{login, mint_admin, mint_invite, register, register_status, setup, unique_name};

/// `reqwest::Client` with a generous timeout for container-backed tests.
fn http() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .expect("reqwest client")
}

/// Read the JSON error envelope from a failing response (or panic on a
/// non-JSON body). Used for status + code assertions.
async fn err_body(resp: reqwest::Response) -> ApiError {
    let status = resp.status();
    let body: ApiError = resp
        .json()
        .await
        .unwrap_or_else(|e| panic!("decode error body at {status}: {e}"));
    body
}

// ---------------------------------------------------------------------------
// Auth: register -> login -> me
// ---------------------------------------------------------------------------

#[tokio::test]
async fn auth_register_login_me_round_trip() {
    let h = setup().await;
    let invite = mint_invite(&h.state).await;
    let name = unique_name("alice");

    let (token, id) = register(&h.base_url, &name, "pw12345", &invite).await;
    assert!(token.len() >= 32, "token looks like a session id");
    assert!(id > 0);

    // Login yields a fresh token for the same account.
    let (token2, id2) = login(&h.base_url, &name, "pw12345").await;
    assert_eq!(id2, id, "login resolves the same account id");
    assert_ne!(token2, token, "each login mints a new session");

    // GET /auth/me echoes the account back from the token.
    let me: AccountInfo = http()
        .get(format!("{}/auth/me", h.base_url))
        .bearer_auth(&token2)
        .send()
        .await
        .expect("me request")
        .json()
        .await
        .expect("decode me");
    assert_eq!(me.id, id);
    assert_eq!(me.username, name);
    assert!(!me.is_admin, "a registered account is not the Instance admin");
}

// ---------------------------------------------------------------------------
// Invite gating + admin mint
// ---------------------------------------------------------------------------

#[tokio::test]
async fn invite_gating_and_admin_mint() {
    let h = setup().await;

    // An admin from the DB directly (not via register, so this works even
    // when other tests have already populated the shared accounts table).
    let (admin_token, _admin_id) = mint_admin(&h.state).await;

    // Admin mints a fresh registration invite via REST.
    let minted: serde_json::Value = http()
        .post(format!("{}/auth/invites", h.base_url))
        .bearer_auth(&admin_token)
        .send()
        .await
        .expect("admin mint")
        .json()
        .await
        .expect("decode minted invite");
    let code = minted
        .get("code")
        .and_then(|v| v.as_str())
        .expect("minted response has a code")
        .to_string();

    // 1) Non-existent invite is rejected with InvalidInvite (400).
    let (status, err) =
        register_status(&h.base_url, &unique_name("ghost"), "pw12345", "no_such_code").await;
    assert_eq!(status, reqwest::StatusCode::BAD_REQUEST);
    let err = err.expect("error body");
    assert_eq!(err.code, ErrorCode::InvalidInvite);

    // 2) A minted invite works exactly once: redeem it, then try again.
    let (_t, _id) = register(&h.base_url, &unique_name("ok"), "pw12345", &code).await;
    let (status, err) =
        register_status(&h.base_url, &unique_name("dup"), "pw12345", &code).await;
    assert_eq!(status, reqwest::StatusCode::BAD_REQUEST);
    let err = err.expect("error body");
    assert_eq!(err.code, ErrorCode::InvalidInvite);

    // 3) A non-admin account may not mint invites.
    let (non_admin_token, _) =
        register(&h.base_url, &unique_name("peasant"), "pw12345", &mint_invite(&h.state).await)
            .await;
    let resp = http()
        .post(format!("{}/auth/invites", h.base_url))
        .bearer_auth(&non_admin_token)
        .send()
        .await
        .expect("non-admin mint");
    assert_eq!(resp.status(), reqwest::StatusCode::FORBIDDEN);
    let err = err_body(resp).await;
    assert_eq!(err.code, ErrorCode::Forbidden);
}

// ---------------------------------------------------------------------------
// Guild create / join / leave
// ---------------------------------------------------------------------------

#[tokio::test]
async fn guild_create_join_leave() {
    let h = setup().await;
    let invite = mint_invite(&h.state).await;
    let (owner_token, owner_id) = register(&h.base_url, &unique_name("owner"), "pw12345", &invite)
        .await;
    let (joiner_token, _joiner_id) =
        register(&h.base_url, &unique_name("joiner"), "pw12345", &mint_invite(&h.state).await)
            .await;

    // Owner creates a guild: response includes the two default channels.
    let guild: GuildInfo = http()
        .post(format!("{}/guilds", h.base_url))
        .bearer_auth(&owner_token)
        .json(&CreateGuildRequest {
            name: "test-guild".into(),
        })
        .send()
        .await
        .expect("create guild")
        .json()
        .await
        .expect("decode guild");
    assert_eq!(guild.owner_id, owner_id);
    assert_eq!(guild.channels.len(), 2);
    assert!(guild
        .channels
        .iter()
        .any(|c| matches!(c.kind, ChannelKind::Text)));
    assert!(guild
        .channels
        .iter()
        .any(|c| matches!(c.kind, ChannelKind::Voice)));

    // Owner mints a guild invite; joiner redeems it.
    let ginv: GuildInviteDto = http()
        .post(format!("{}/guilds/{}/invites", h.base_url, guild.id))
        .bearer_auth(&owner_token)
        .json(&CreateGuildInviteRequest {
            max_uses: None,
            ttl_secs: None,
        })
        .send()
        .await
        .expect("mint guild invite")
        .json()
        .await
        .expect("decode guild invite");
    assert_eq!(ginv.guild_id, guild.id);
    assert_eq!(ginv.uses, 0);

    let joined: GuildInfo = http()
        .post(format!("{}/guilds/join", h.base_url))
        .bearer_auth(&joiner_token)
        .json(&JoinGuildRequest {
            code: ginv.code.clone(),
        })
        .send()
        .await
        .expect("join guild")
        .json()
        .await
        .expect("decode joined guild");
    assert_eq!(joined.id, guild.id);

    // Both members see the guild in their list.
    let owner_guilds: Vec<GuildInfo> = http()
        .get(format!("{}/guilds", h.base_url))
        .bearer_auth(&owner_token)
        .send()
        .await
        .expect("list owner guilds")
        .json()
        .await
        .expect("decode owner guilds");
    assert!(owner_guilds.iter().any(|g| g.id == guild.id));

    // Joiner leaves (owner-leaving is a separate v1 edge case not under
    // test here); the server returns 204 on success.
    let leave = http()
        .post(format!("{}/guilds/{}/leave", h.base_url, guild.id))
        .bearer_auth(&joiner_token)
        .send()
        .await
        .expect("leave guild");
    assert_eq!(leave.status(), reqwest::StatusCode::NO_CONTENT);

    // Re-joining an already-left guild via the same code works only if the
    // invite still has uses; here it was unlimited, so a fresh join
    // succeeds. Confirms the leave actually removed membership.
    let rejoined = http()
        .post(format!("{}/guilds/join", h.base_url))
        .bearer_auth(&joiner_token)
        .json(&JoinGuildRequest {
            code: ginv.code.clone(),
        })
        .send()
        .await
        .expect("rejoin guild");
    assert!(rejoined.status().is_success());
}

// ---------------------------------------------------------------------------
// Message send / page / delete
// ---------------------------------------------------------------------------

#[tokio::test]
async fn message_send_page_delete() {
    let h = setup().await;
    let invite = mint_invite(&h.state).await;
    let (a_token, a_id) = register(&h.base_url, &unique_name("msg_a"), "pw12345", &invite).await;
    let (b_token, b_id) =
        register(&h.base_url, &unique_name("msg_b"), "pw12345", &mint_invite(&h.state).await).await;

    // A befriends B (B accepts) so a DM channel can be opened: that channel
    // is where both sides can read each other's messages.
    let _: FriendList = http()
        .post(format!("{}/friends/requests", h.base_url))
        .bearer_auth(&a_token)
        .json(&serde_json::json!({ "account_id": b_id }))
        .send()
        .await
        .expect("friend request")
        .json()
        .await
        .expect("decode friend list");
    let _: FriendList = http()
        .post(format!("{}/friends/requests/{}/accept", h.base_url, a_id))
        .bearer_auth(&b_token)
        .send()
        .await
        .expect("accept")
        .json()
        .await
        .expect("decode friend list");

    let dm: DmChannel = http()
        .post(format!("{}/dms", h.base_url))
        .bearer_auth(&a_token)
        .json(&OpenDmRequest { account_id: b_id })
        .send()
        .await
        .expect("open dm")
        .json()
        .await
        .expect("decode dm");
    let chan = dm.channel.id;

    // Send three messages; A receives the created dto back, B is not echoed
    // (the REST response goes only to the sender). Content is opaque
    // ciphertext to the server: the only validation is that it is base64.
    let contents = ["YQ==", "Yg==", "Yw=="]; // 1-byte payloads "a", "b", "c"
    let mut ids = Vec::new();
    for c in contents {
        let dto: MessageDto = http()
            .post(format!("{}/channels/{}/messages", h.base_url, chan))
            .bearer_auth(&a_token)
            .json(&SendMessageRequest {
                kind: MessageKind::Chat,
                content: c.into(),
                reply_to: None,
                attachment_id: None,
            })
            .send()
            .await
            .expect("send message")
            .json()
            .await
            .expect("decode message");
        assert_eq!(dto.channel_id, chan);
        assert_eq!(dto.sender_id, a_id);
        assert_eq!(dto.content, c);
        ids.push(dto.id);
    }
    // ids are monotonically increasing per channel.
    assert!(ids[0] < ids[1] && ids[1] < ids[2]);

    // Newest page: all three, oldest-first.
    let page: MessagePage = http()
        .get(format!("{}/channels/{}/messages", h.base_url, chan))
        .bearer_auth(&a_token)
        .send()
        .await
        .expect("page newest")
        .json()
        .await
        .expect("decode page");
    assert_eq!(page.messages.len(), 3);
    assert!(!page.has_more);
    assert_eq!(
        page.messages.iter().map(|m| m.id).collect::<Vec<_>>(),
        ids
    );

    // Page with `before=<oldest>` returns nothing older.
    let older: MessagePage = http()
        .get(format!(
            "{}/channels/{}/messages?before={}&limit=10",
            h.base_url, chan, ids[0]
        ))
        .bearer_auth(&a_token)
        .send()
        .await
        .expect("page older")
        .json()
        .await
        .expect("decode older page");
    assert!(older.messages.is_empty());
    assert!(!older.has_more);

    // Delete the middle message; only the sender may delete.
    let del = http()
        .delete(format!(
            "{}/channels/{}/messages/{}",
            h.base_url, chan, ids[1]
        ))
        .bearer_auth(&a_token)
        .send()
        .await
        .expect("delete own message");
    assert_eq!(del.status(), reqwest::StatusCode::NO_CONTENT);

    // B cannot delete A's message -> 403 Forbidden.
    let del_other = http()
        .delete(format!(
            "{}/channels/{}/messages/{}",
            h.base_url, chan, ids[0]
        ))
        .bearer_auth(&b_token)
        .send()
        .await
        .expect("delete other's message");
    assert_eq!(del_other.status(), reqwest::StatusCode::FORBIDDEN);

    // History reflects the deletion.
    let after: MessagePage = http()
        .get(format!("{}/channels/{}/messages", h.base_url, chan))
        .bearer_auth(&a_token)
        .send()
        .await
        .expect("page after delete")
        .json()
        .await
        .expect("decode page after delete");
    assert_eq!(after.messages.len(), 2);
    assert!(!after.messages.iter().any(|m| m.id == ids[1]));
}

// ---------------------------------------------------------------------------
// Attachment create / download + Tier-1 IDOR fix
// ---------------------------------------------------------------------------

#[tokio::test]
async fn attachment_create_download_and_idor_fix() {
    let h = setup().await;
    let invite = mint_invite(&h.state).await;
    let (owner_token, _owner_id) =
        register(&h.base_url, &unique_name("att_owner"), "pw12345", &invite).await;
    let (outsider_token, _) =
        register(&h.base_url, &unique_name("att_out"), "pw12345", &mint_invite(&h.state).await)
            .await;

    // Owner reserves an attachment and uploads ciphertext bytes to the
    // presigned PUT URL (no auth header: the SigV4 signature in the URL IS
    // the authorization).
    let created: CreateAttachmentResponse = http()
        .post(format!("{}/attachments", h.base_url))
        .bearer_auth(&owner_token)
        .json(&CreateAttachmentRequest {
            name: "secret.bin".into(),
            size: 5,
            nonce: "bm9uY2Ux".into(), // 1..128 chars
        })
        .send()
        .await
        .expect("create attachment")
        .json()
        .await
        .expect("decode create response");
    assert!(created.attachment.id > 0);
    assert!(created.attachment.encrypted);

    let put = reqwest::Client::new()
        .put(&created.upload_url)
        .body(b"abcde".to_vec())
        .send()
        .await
        .expect("upload to presigned url");
    assert!(
        put.status().is_success(),
        "presigned PUT should succeed, got {}",
        put.status()
    );

    // Owner can mint their own download URL.
    let dl: DownloadUrlResponse = http()
        .get(format!(
            "{}/attachments/{}/download-url",
            h.base_url, created.attachment.id
        ))
        .bearer_auth(&owner_token)
        .send()
        .await
        .expect("owner download-url")
        .json()
        .await
        .expect("decode download-url");
    assert!(!dl.url.is_empty());
    assert!(dl.expires_at_ms > 0);

    // Tier-1 IDOR fix: an account that is NOT a member of any channel the
    // attachment was shared into must NOT be able to mint a download URL.
    // The outsider shares no guild and no DM with the owner, so this MUST
    // come back 403. (Until the membership check lands in
    // attachments::download_url, this assertion fails — pinning the
    // desired behavior is the point of the test.)
    let outsider_dl = http()
        .get(format!(
            "{}/attachments/{}/download-url",
            h.base_url, created.attachment.id
        ))
        .bearer_auth(&outsider_token)
        .send()
        .await
        .expect("outsider download-url");
    assert_eq!(
        outsider_dl.status(),
        reqwest::StatusCode::FORBIDDEN,
        "Tier-1 IDOR fix: non-member must not mint a download URL"
    );
}

// ---------------------------------------------------------------------------
// Friend request / accept / remove
// ---------------------------------------------------------------------------

#[tokio::test]
async fn friend_request_accept_remove() {
    let h = setup().await;
    let invite = mint_invite(&h.state).await;
    let (a_token, a_id) = register(&h.base_url, &unique_name("fr_a"), "pw12345", &invite).await;
    let (b_token, b_id) =
        register(&h.base_url, &unique_name("fr_b"), "pw12345", &mint_invite(&h.state).await).await;

    // A sends a friend request to B: A's outgoing list gains B.
    let a_list: FriendList = http()
        .post(format!("{}/friends/requests", h.base_url))
        .bearer_auth(&a_token)
        .json(&serde_json::json!({ "account_id": b_id }))
        .send()
        .await
        .expect("send friend request")
        .json()
        .await
        .expect("decode a list");
    assert!(a_list.outgoing.iter().any(|b| b.id == b_id));
    assert!(a_list.friends.is_empty());

    // B sees the incoming request.
    let b_list: FriendList = http()
        .get(format!("{}/friends", h.base_url))
        .bearer_auth(&b_token)
        .send()
        .await
        .expect("b friends")
        .json()
        .await
        .expect("decode b list");
    assert!(b_list.incoming.iter().any(|a| a.id == a_id));

    // B accepts; both sides become friends.
    let b_after: FriendList = http()
        .post(format!("{}/friends/requests/{}/accept", h.base_url, a_id))
        .bearer_auth(&b_token)
        .send()
        .await
        .expect("accept")
        .json()
        .await
        .expect("decode b after accept");
    assert!(b_after.friends.iter().any(|a| a.id == a_id));

    let a_after: FriendList = http()
        .get(format!("{}/friends", h.base_url))
        .bearer_auth(&a_token)
        .send()
        .await
        .expect("a friends after accept")
        .json()
        .await
        .expect("decode a after accept");
    assert!(a_after.friends.iter().any(|b| b.id == b_id));

    // A removes B; the relationship ends on both sides (204).
    let remove = http()
        .delete(format!("{}/friends/{}", h.base_url, b_id))
        .bearer_auth(&a_token)
        .send()
        .await
        .expect("remove friend");
    assert_eq!(remove.status(), reqwest::StatusCode::NO_CONTENT);

    let a_final: FriendList = http()
        .get(format!("{}/friends", h.base_url))
        .bearer_auth(&a_token)
        .send()
        .await
        .expect("a friends after remove")
        .json()
        .await
        .expect("decode a after remove");
    assert!(!a_final.friends.iter().any(|b| b.id == b_id));
    assert!(a_final.incoming.is_empty());
    assert!(a_final.outgoing.is_empty());
}
