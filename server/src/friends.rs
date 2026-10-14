//! Friend graph endpoints: list, request (with reverse-request auto-accept),
//! accept, decline/cancel, remove.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use bysyc_common::protocol::{AccountBrief, FriendList, WsServerBody};
use serde::Deserialize;

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
    let friends: Vec<BriefRow> = sqlx::query_as(
        "SELECT b.id, b.username, b.identity_key FROM friends f \
         JOIN accounts b ON b.id = CASE WHEN f.a = $1 THEN f.b ELSE f.a END \
         WHERE f.a = $1 OR f.b = $1",
    )
    .bind(me)
    .fetch_all(&state.pg)
    .await?;
    let incoming: Vec<BriefRow> = sqlx::query_as(
        "SELECT a.id, a.username, a.identity_key FROM friend_requests r \
         JOIN accounts a ON a.id = r.from_id WHERE r.to_id = $1",
    )
    .bind(me)
    .fetch_all(&state.pg)
    .await?;
    let outgoing: Vec<BriefRow> = sqlx::query_as(
        "SELECT a.id, a.username, a.identity_key FROM friend_requests r \
         JOIN accounts a ON a.id = r.to_id WHERE r.from_id = $1",
    )
    .bind(me)
    .fetch_all(&state.pg)
    .await?;
    Ok(FriendList {
        friends: with_online(state, friends).await?,
        incoming: with_online(state, incoming).await?,
        outgoing: with_online(state, outgoing).await?,
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
        with_online(&state, vec![row]).await?.pop().expect("one brief"),
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
    let peer_row: BriefRow = sqlx::query_as(BRIEF_SQL)
        .bind(peer)
        .fetch_optional(&state.pg)
        .await?
        .ok_or_else(|| ApiError::not_found("no such account"))?;

    let friends: Option<i64> = sqlx::query_scalar(
        "SELECT a FROM friends WHERE a = LEAST($1, $2) AND b = GREATEST($1, $2)",
    )
    .bind(me)
    .bind(peer)
    .fetch_optional(&state.pg)
    .await?;
    if friends.is_some() {
        return Err(ApiError::invalid("already friends with this account"));
    }

    // The peer already asked us: sending back auto-accepts both requests.
    let reverse: Option<i32> =
        sqlx::query_scalar("SELECT 1 FROM friend_requests WHERE from_id = $1 AND to_id = $2")
            .bind(peer)
            .bind(me)
            .fetch_optional(&state.pg)
            .await?;
    if reverse.is_some() {
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

        let my_brief = brief(&state, me).await?;
        let peer_brief = with_online(&state, vec![peer_row])
            .await?
            .pop()
            .expect("one brief");
        events::publish_to_account(
            &state.redis,
            peer,
            &WsServerBody::FriendRequestAccepted { by: my_brief },
        )
        .await?;
        events::publish_to_account(
            &state.redis,
            me,
            &WsServerBody::FriendRequestAccepted { by: peer_brief },
        )
        .await?;
        return Ok(Json(friend_list(&state, me).await?));
    }

    // We already asked them: idempotent no-op.
    let outgoing: Option<i32> =
        sqlx::query_scalar("SELECT 1 FROM friend_requests WHERE from_id = $1 AND to_id = $2")
            .bind(me)
            .bind(peer)
            .fetch_optional(&state.pg)
            .await?;
    if outgoing.is_some() {
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
        &state.redis,
        peer,
        &WsServerBody::FriendRequested { from: my_brief },
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

    let my_brief = brief(&state, me).await?;
    events::publish_to_account(
        &state.redis,
        peer,
        &WsServerBody::FriendRequestAccepted { by: my_brief },
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
    events::publish_to_account(
        &state.redis,
        me,
        &WsServerBody::FriendRemoved { account_id: peer },
    )
    .await?;
    events::publish_to_account(
        &state.redis,
        peer,
        &WsServerBody::FriendRemoved { account_id: me },
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}
