//! Friend graph endpoints: list, request (with reverse-request auto-accept),
//! accept, decline/cancel, remove.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use bysyc_common::protocol::{AccountBrief, FriendList, WsServerBody};
use serde::Deserialize;
use std::collections::HashMap;

use crate::db::AppState;
use crate::error::{ApiError, ApiResult};
use crate::events;
use crate::session::Authed;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/friends", get(list))
        .route("/friends/requests", post(send_request))
        .route("/friends/requests/{account_id}/accept", post(accept))
        .route("/friends/requests/{account_id}/decline", post(decline))
        .route("/friends/{account_id}", delete(remove))
        .route("/accounts/by-username/{username}", get(lookup_by_username))
}

#[derive(Deserialize)]
struct SendFriendRequest {
    account_id: i64,
}

/// (id, username, identity_key)
type BriefRow = (i64, String, Option<String>);

const BRIEF_SQL: &str = "SELECT id, username, identity_key FROM accounts WHERE id = $1";

/// One row of the combined `send_request` decision query: the peer's brief
/// columns plus the three flags the handler branches on. Folds what used to
/// be four sequential round trips (peer existence, already-friends,
/// reverse-request, outgoing-request) into a single CTE so one round trip
/// decides accept-vs-reject-vs-insert.
type SendRequestRow = (i64, String, Option<String>, bool, bool, bool);

const SEND_REQUEST_SQL: &str = "\
WITH peer AS ( \
    SELECT id, username, identity_key FROM accounts WHERE id = $2 \
), fr AS ( \
    SELECT \
        EXISTS(SELECT 1 FROM friends WHERE a = LEAST($1, $2) AND b = GREATEST($1, $2)) AS already_friends, \
        EXISTS(SELECT 1 FROM friend_requests WHERE from_id = $2 AND to_id = $1) AS reverse_present, \
        EXISTS(SELECT 1 FROM friend_requests WHERE from_id = $1 AND to_id = $2) AS outgoing_present \
) \
SELECT p.id, p.username, p.identity_key, fr.already_friends, fr.reverse_present, fr.outgoing_present \
FROM peer p CROSS JOIN fr";

/// Attach online flags to a batch of account rows with one Redis pipeline.
/// Online = `EXISTS presence:{id}` (the WS gateway maintains those keys).
async fn with_online(state: &AppState, rows: Vec<BriefRow>) -> Result<Vec<AccountBrief>, ApiError> {
    if rows.is_empty() {
        return Ok(Vec::new());
    }
    let mut pipe = redis::Pipeline::new();
    for (id, _, _) in &rows {
        pipe.cmd("EXISTS").arg(format!("presence:{id}"));
    }
    let mut conn = state.redis.clone();
    let online: Vec<bool> = pipe.query_async(&mut conn).await?;
    Ok(rows
        .into_iter()
        .zip(online)
        .map(|((id, username, identity_key), online)| AccountBrief {
            id,
            username,
            identity_key: identity_key.unwrap_or_default(),
            online,
        })
        .collect())
}

async fn brief(state: &AppState, id: i64) -> Result<AccountBrief, ApiError> {
    let row: Option<BriefRow> = sqlx::query_as(BRIEF_SQL)
        .bind(id)
        .fetch_optional(&state.pg)
        .await?;
    let row = row.ok_or_else(|| ApiError::not_found("no such account"))?;
    Ok(with_online(state, vec![row])
        .await?
        .pop()
        .expect("one brief"))
}

async fn friend_list(state: &AppState, me: i64) -> Result<FriendList, ApiError> {
    let (friends, incoming, outgoing) = tokio::join!(
        sqlx::query_as::<_, BriefRow>(
            "SELECT b.id, b.username, b.identity_key FROM friends f \
             JOIN accounts b ON b.id = CASE WHEN f.a = $1 THEN f.b ELSE f.a END \
             WHERE f.a = $1 OR f.b = $1",
        )
        .bind(me)
        .fetch_all(&state.pg),
        sqlx::query_as::<_, BriefRow>(
            "SELECT a.id, a.username, a.identity_key FROM friend_requests r \
             JOIN accounts a ON a.id = r.from_id WHERE r.to_id = $1",
        )
        .bind(me)
        .fetch_all(&state.pg),
        sqlx::query_as::<_, BriefRow>(
            "SELECT a.id, a.username, a.identity_key FROM friend_requests r \
             JOIN accounts a ON a.id = r.to_id WHERE r.from_id = $1",
        )
        .bind(me)
        .fetch_all(&state.pg),
    );
    let (friends, incoming, outgoing) = (friends?, incoming?, outgoing?);

    // One merged presence pipeline for all three lists; an account can
    // appear in more than one list, so map results back by account id.
    let mut ids: Vec<i64> = friends
        .iter()
        .chain(&incoming)
        .chain(&outgoing)
        .map(|(id, _, _)| *id)
        .collect();
    ids.sort_unstable();
    ids.dedup();
    let mut online_by_id: HashMap<i64, bool> = HashMap::new();
    if !ids.is_empty() {
        let mut pipe = redis::Pipeline::new();
        for id in &ids {
            pipe.cmd("EXISTS").arg(format!("presence:{id}"));
        }
        let mut conn = state.redis.clone();
        let online: Vec<bool> = pipe.query_async(&mut conn).await?;
        online_by_id = ids.into_iter().zip(online).collect();
    }
    let attach = |rows: Vec<BriefRow>| -> Vec<AccountBrief> {
        rows.into_iter()
            .map(|(id, username, identity_key)| AccountBrief {
                id,
                username,
                identity_key: identity_key.unwrap_or_default(),
                online: online_by_id.get(&id).copied().unwrap_or(false),
            })
            .collect()
    };
    Ok(FriendList {
        friends: attach(friends),
        incoming: attach(incoming),
        outgoing: attach(outgoing),
    })
}

/// Resolve a username to an [`AccountBrief`] (online flag included) so the
/// client can turn "add friend by username" into an account id before
/// `POST /friends/requests`. Unknown username → NotFound.
async fn lookup_by_username(
    State(state): State<AppState>,
    Authed(_me): Authed,
    Path(username): Path<String>,
) -> ApiResult<Json<AccountBrief>> {
    let row: Option<BriefRow> =
        sqlx::query_as("SELECT id, username, identity_key FROM accounts WHERE username = $1")
            .bind(&username)
            .fetch_optional(&state.pg)
            .await?;
    let row = row.ok_or_else(|| ApiError::not_found("no such account"))?;
    Ok(Json(
        with_online(&state, vec![row])
            .await?
            .pop()
            .expect("one brief"),
    ))
}

async fn list(State(state): State<AppState>, Authed(me): Authed) -> ApiResult<Json<FriendList>> {
    Ok(Json(friend_list(&state, me).await?))
}

async fn send_request(
    State(state): State<AppState>,
    Authed(me): Authed,
    Json(req): Json<SendFriendRequest>,
) -> ApiResult<Json<FriendList>> {
    let peer = req.account_id;
    if peer == me {
        return Err(ApiError::invalid("cannot send yourself a friend request"));
    }

    // One round trip resolves the peer's existence + brief columns AND the
    // three flags the handler branches on (already-friends, reverse-request
    // present, outgoing-request present). The previous shape paid four
    // sequential round trips here before any write. `peer` is empty in the
    // CTE when the account does not exist, so CROSS JOIN yields nothing and
    // fetch_optional comes back None -> NotFound.
    let row: Option<SendRequestRow> = sqlx::query_as(SEND_REQUEST_SQL)
        .bind(me)
        .bind(peer)
        .fetch_optional(&state.pg)
        .await?;
    let (peer_id, peer_username, peer_identity_key, already_friends, reverse_present, outgoing_present) =
        row.ok_or_else(|| ApiError::not_found("no such account"))?;
    if already_friends {
        return Err(ApiError::invalid("already friends with this account"));
    }

    // The peer already asked us: sending back auto-accepts both requests.
    if reverse_present {
        let mut tx = state.pg.begin().await?;
        sqlx::query(
            "DELETE FROM friend_requests \
             WHERE (from_id = $1 AND to_id = $2) OR (from_id = $2 AND to_id = $1)",
        )
        .bind(me)
        .bind(peer)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO friends (a, b) VALUES (LEAST($1, $2), GREATEST($1, $2)) \
             ON CONFLICT DO NOTHING",
        )
        .bind(me)
        .bind(peer)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;

        // Our own row and the peer's presence flag are independent; fetch
        // them concurrently. The caller's brief is definitionally online —
        // this request proves it — so skip the Redis probe for it. The peer's
        // brief columns came back on the decision query above, so only the
        // online flag still needs Redis.
        let peer_row: BriefRow = (peer_id, peer_username, peer_identity_key);
        let (my_row, peer_briefs) = tokio::join!(
            sqlx::query_as::<_, BriefRow>(BRIEF_SQL)
                .bind(me)
                .fetch_optional(&state.pg),
            with_online(&state, vec![peer_row]),
        );
        let my_row = my_row?.ok_or_else(|| ApiError::not_found("no such account"))?;
        let my_brief = AccountBrief {
            id: my_row.0,
            username: my_row.1,
            identity_key: my_row.2.unwrap_or_default(),
            online: true,
        };
        let peer_brief = peer_briefs?.pop().expect("one brief");
        let to_peer_body = WsServerBody::FriendRequestAccepted { by: my_brief };
        let to_me_body = WsServerBody::FriendRequestAccepted { by: peer_brief };
        // Both sides hear about the new friendship in one pipelined round
        // trip.
        events::FanOut::new()
            .account(peer, to_peer_body)
            .account(me, to_me_body)
            .flush(&state.redis_events)
            .await?;
        return Ok(Json(friend_list(&state, me).await?));
    }

    // We already asked them: idempotent no-op.
    if outgoing_present {
        return Ok(Json(friend_list(&state, me).await?));
    }

    sqlx::query(
        "INSERT INTO friend_requests (from_id, to_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
    )
    .bind(me)
    .bind(peer)
    .execute(&state.pg)
    .await?;
    let my_brief = brief(&state, me).await?;
    events::publish_to_account(
        &state.redis_events,
        peer,
        WsServerBody::FriendRequested { from: my_brief },
    )
    .await?;
    Ok(Json(friend_list(&state, me).await?))
}

async fn accept(
    State(state): State<AppState>,
    Authed(me): Authed,
    Path(peer): Path<i64>,
) -> ApiResult<Json<FriendList>> {
    let mut tx = state.pg.begin().await?;
    let deleted = sqlx::query("DELETE FROM friend_requests WHERE from_id = $1 AND to_id = $2")
        .bind(peer)
        .bind(me)
        .execute(&mut *tx)
        .await?;
    if deleted.rows_affected() == 0 {
        return Err(ApiError::invalid(
            "no pending friend request from this account",
        ));
    }
    sqlx::query(
        "INSERT INTO friends (a, b) VALUES (LEAST($1, $2), GREATEST($1, $2)) \
         ON CONFLICT DO NOTHING",
    )
    .bind(me)
    .bind(peer)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    // The accepter is definitionally online — this request proves it — so
    // build the brief from our own row without the Redis probe.
    let my_row: BriefRow = sqlx::query_as(BRIEF_SQL)
        .bind(me)
        .fetch_optional(&state.pg)
        .await?
        .ok_or_else(|| ApiError::not_found("no such account"))?;
    let my_brief = AccountBrief {
        id: my_row.0,
        username: my_row.1,
        identity_key: my_row.2.unwrap_or_default(),
        online: true,
    };
    events::publish_to_account(
        &state.redis_events,
        peer,
        WsServerBody::FriendRequestAccepted { by: my_brief },
    )
    .await?;
    Ok(Json(friend_list(&state, me).await?))
}

/// Declines an incoming request; per the protocol doc it also cancels the
/// caller's own outgoing request to that account.
async fn decline(
    State(state): State<AppState>,
    Authed(me): Authed,
    Path(peer): Path<i64>,
) -> ApiResult<Json<FriendList>> {
    sqlx::query(
        "DELETE FROM friend_requests \
         WHERE (from_id = $1 AND to_id = $2) OR (from_id = $2 AND to_id = $1)",
    )
    .bind(peer)
    .bind(me)
    .execute(&state.pg)
    .await?;
    Ok(Json(friend_list(&state, me).await?))
}

async fn remove(
    State(state): State<AppState>,
    Authed(me): Authed,
    Path(peer): Path<i64>,
) -> ApiResult<StatusCode> {
    let deleted =
        sqlx::query("DELETE FROM friends WHERE a = LEAST($1, $2) AND b = GREATEST($1, $2)")
            .bind(me)
            .bind(peer)
            .execute(&state.pg)
            .await?;
    if deleted.rows_affected() == 0 {
        return Err(ApiError::not_found("not friends with this account"));
    }
    let to_me_body = WsServerBody::FriendRemoved { account_id: peer };
    let to_peer_body = WsServerBody::FriendRemoved { account_id: me };
    // One pipelined round trip carries both removal notices.
    events::FanOut::new()
        .account(me, to_me_body)
        .account(peer, to_peer_body)
        .flush(&state.redis_events)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
