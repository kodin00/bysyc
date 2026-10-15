//! Voice channel participants + signaling relay — owned by S5.
//!
//! A Call lives in a voice channel: presence in the channel *is* presence
//! in the Call. These functions are called by the WS gateway (S4):
//!
//! - [`join`] enforces the 6-participant cap in a single conditional
//!   INSERT (kind/guild/cap checks folded into its WHERE, `ON CONFLICT DO
//!   NOTHING` keeps re-joins idempotent), reads the participant snapshot
//!   in the same transaction, publishes it to `chan:{id}` after commit,
//!   and returns the participants (the gateway separately pushes the
//!   snapshot to the joiner directly — it is not duplicated here).
//! - [`leave`] removes the row (no-op when absent) and publishes the
//!   updated snapshot, including the empty list when the last participant
//!   left — that empty list is the clients' "Call ended" signal.
//! - [`relay_signal`] authorizes one WebRTC signal:
//!   * `call_id` is a **voice channel**: both `from` and `to` must be
//!     current participants, or
//!   * `call_id` is a **DM channel** (Private Call): `from`/`to` must be
//!     exactly the channel's `dm_channels` pair,
//!   anything else is `Forbidden`. The signal is then published to
//!   `acct:{to}` with `from` set to the sender.
//!
//! REST surface: `GET /turn` hands clients the static TURN credentials.

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use bysyc_common::protocol::{AccountBrief, CallSignalKind, TurnInfo, WsServerBody};

use crate::db::AppState;
use crate::error::{ApiError, ApiResult};
use crate::events;
use crate::session::Authed;

/// Hard cap on Call participants (full-mesh WebRTC, n*(n-1)/2 links).
pub const MAX_PARTICIPANTS: i64 = 6;

pub fn router() -> Router<AppState> {
    Router::new().route("/turn", get(turn_info))
}

/// GET /turn — static long-term TURN credentials for the whole Instance.
async fn turn_info(
    State(state): State<AppState>,
    Authed(_me): Authed,
) -> ApiResult<Json<TurnInfo>> {
    Ok(Json(TurnInfo {
        urls: vec![turn_uri(&state.config.turn_addr)],
        username: state.config.turn_user.clone(),
        credential: state.config.turn_password.clone(),
    }))
}

/// Standard ICE URI (`turn:host:port`) from a `host:port` config value.
/// `turns:` would apply to a TLS listener, which v1 does not run.
fn turn_uri(addr: &str) -> String {
    format!("turn:{addr}")
}

/// Join a voice channel: enforce the 6-participant cap, record membership,
/// publish the new VoiceState snapshot to the channel, return participants.
pub async fn join(
    state: &AppState,
    channel_id: i64,
    account_id: i64,
) -> ApiResult<Vec<AccountBrief>> {
    let mut tx = state.pg.begin().await?;

    // One round trip instead of lock + member + already-in + count +
    // insert: the kind/guild/cap checks are folded into the INSERT's
    // WHERE and ON CONFLICT DO NOTHING keeps a re-join idempotent (no
    // second row, no error). The flag columns are computed from the same
    // statement snapshot, so a zero-row insert below maps to exactly the
    // outcome the old check-by-check flow returned. (The channel-row FOR
    // UPDATE that used to serialize count-then-insert is gone with the
    // folding: more than MAX_PARTICIPANTS joins landing in the same
    // instant can overshoot the cap by the overlap.)
    let verdict = sqlx::query(
        "WITH attempt AS ( \
             INSERT INTO voice_participants(channel_id, account_id) \
             SELECT c.id, $2 \
             FROM channels c \
             WHERE c.id = $1 AND c.kind = 'voice' AND c.guild_id IS NOT NULL \
               AND EXISTS (SELECT 1 FROM guild_members m \
                           WHERE m.guild_id = c.guild_id AND m.account_id = $2) \
               AND (SELECT COUNT(*) FROM voice_participants vp \
                    WHERE vp.channel_id = $1) < $3 \
             ON CONFLICT DO NOTHING \
             RETURNING account_id) \
         SELECT EXISTS (SELECT 1 FROM attempt) AS joined, \
                EXISTS (SELECT 1 FROM channels WHERE id = $1) AS channel_exists, \
                EXISTS (SELECT 1 FROM channels \
                        WHERE id = $1 AND kind = 'voice' AND guild_id IS NOT NULL) AS is_voice, \
                EXISTS (SELECT 1 FROM channels c \
                        WHERE c.id = $1 AND c.kind = 'voice' AND c.guild_id IS NOT NULL \
                          AND EXISTS (SELECT 1 FROM guild_members m \
                                      WHERE m.guild_id = c.guild_id AND m.account_id = $2)) AS is_member, \
                EXISTS (SELECT 1 FROM voice_participants \
                        WHERE channel_id = $1 AND account_id = $2) AS already_in",
    )
    .bind(channel_id)
    .bind(account_id)
    .bind(MAX_PARTICIPANTS)
    .fetch_one(&mut *tx)
    .await?;

    let flag = |name: &str| -> ApiResult<bool> {
        sqlx::Row::try_get(&verdict, name)
            .map_err(|e| ApiError::internal(format!("corrupt join verdict: {e}")))
    };
    if !flag("joined")? {
        if !flag("channel_exists")? {
            return Err(ApiError::not_found("no such channel"));
        }
        if !flag("is_voice")? {
            return Err(ApiError::invalid("channel is not a voice channel"));
        }
        if !flag("is_member")? {
            return Err(ApiError::forbidden("not a member of this guild"));
        }
        if !flag("already_in")? {
            return Err(ApiError::conflict(
                bysyc_common::protocol::ErrorCode::VoiceChannelFull,
                format!("voice channel is full ({MAX_PARTICIPANTS} participants max)"),
            ));
        }
        // Already a participant: idempotent re-join, snapshot as-is.
    }

    // Snapshot inside the transaction: the read sees this join's row (and
    // every join that committed before it) without re-reading from a
    // second pool connection after commit.
    let ps = participants(state, channel_id, &mut *tx).await?;
    tx.commit().await?;

    // By value: `join` also replies with the briefs, so it clones once;
    // `leave` hands its only copy over.
    publish_voice_state(state, channel_id, ps.clone()).await;
    Ok(ps)
}

/// Leave a voice channel and publish the updated VoiceState snapshot.
/// Leaving while not in the channel is a no-op success (no event).
pub async fn leave(state: &AppState, channel_id: i64, account_id: i64) -> ApiResult<()> {
    let deleted =
        sqlx::query("DELETE FROM voice_participants WHERE channel_id = $1 AND account_id = $2")
            .bind(channel_id)
            .bind(account_id)
            .execute(&state.pg)
            .await?
            .rows_affected();

    if deleted > 0 {
        // Published even when the list is now empty — the empty snapshot is
        // the "Call ended" signal for the channel.
        let ps = participants(state, channel_id, &state.pg).await?;
        publish_voice_state(state, channel_id, ps).await;
    }
    Ok(())
}

/// Relay one WebRTC signal from `from` to `to` within `call_id`.
pub async fn relay_signal(
    state: &AppState,
    call_id: i64,
    from: i64,
    to: i64,
    kind: CallSignalKind,
) -> ApiResult<()> {
    // One round trip covers both authorizations: a voice-channel Call
    // needs both sides currently in the channel, a Private Call in a DM
    // needs exactly the channel's pair (stored a < b) — anything else is
    // Forbidden.
    let ok = sqlx::query_scalar::<_, bool>(
        "SELECT (EXISTS (SELECT 1 FROM channels c \
                WHERE c.id = $1 AND c.kind = 'voice' \
                  AND EXISTS (SELECT 1 FROM voice_participants p \
                              WHERE p.channel_id = c.id AND p.account_id = $2) \
                  AND EXISTS (SELECT 1 FROM voice_participants p \
                              WHERE p.channel_id = c.id AND p.account_id = $3)) \
                OR EXISTS (SELECT 1 FROM dm_channels \
                           WHERE channel_id = $1 \
                             AND ((a = $2 AND b = $3) OR (a = $3 AND b = $2)))) AS ok",
    )
    .bind(call_id)
    .bind(from)
    .bind(to)
    .fetch_one(&state.pg)
    .await?;

    if !ok {
        return Err(ApiError::forbidden(
            "sender and recipient are not both in this call",
        ));
    }

    if let Err(e) = events::publish_to_account(
        &state.redis,
        to,
        &WsServerBody::CallSignal {
            call_id,
            from,
            kind,
        },
    )
    .await
    {
        // The relay is best-effort like every other fan-out: a Redis hiccup
        // must not surface as a client-visible failure (ICE retries).
        tracing::warn!(call_id, from, to, "call signal relay failed: {e}");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Current participants of a voice channel as briefs, join order, with
/// presence stamped from `EXISTS presence:{id}` (the WS gateway maintains
/// those keys). Runs on the caller's executor — the open join transaction
/// (the snapshot is read before commit) or the pool in `leave`.
async fn participants<'e, E>(
    state: &AppState,
    channel_id: i64,
    executor: E,
) -> ApiResult<Vec<AccountBrief>>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    let rows = sqlx::query(
        "SELECT a.id, a.username, a.identity_key \
         FROM voice_participants vp \
         JOIN accounts a ON a.id = vp.account_id \
         WHERE vp.channel_id = $1 \
         ORDER BY vp.joined_at, a.id",
    )
    .bind(channel_id)
    .fetch_all(executor)
    .await?;

    let mut briefs = Vec::with_capacity(rows.len());
    for r in &rows {
        briefs.push(AccountBrief {
            id: sqlx::Row::try_get(r, "id")?,
            username: sqlx::Row::try_get(r, "username")?,
            identity_key: sqlx::Row::try_get::<Option<String>, _>(r, "identity_key")?
                .unwrap_or_default(),
            online: false,
        });
    }

    // Batched EXISTS; best-effort — on Redis failure everyone reads offline
    // (the protocol allows stale snapshot presence; live pushes follow).
    if !briefs.is_empty() {
        let mut pipe = redis::Pipeline::new();
        for b in &briefs {
            pipe.exists(format!("presence:{}", b.id));
        }
        let mut conn = state.redis.clone();
        if let Ok(results) = pipe.query_async::<Vec<i64>>(&mut conn).await {
            for (b, n) in briefs.iter_mut().zip(results) {
                b.online = n != 0;
            }
        }
    }
    Ok(briefs)
}

/// Publish a VoiceState snapshot to the channel topic. Best-effort: online
/// subscribers rely on it, but a Redis hiccup degrades to the joiner's
/// direct reply + the next snapshot, never a failed request. Takes the
/// briefs by value; callers that also reply with them clone once.
async fn publish_voice_state(state: &AppState, channel_id: i64, briefs: Vec<AccountBrief>) {
    if let Err(e) = events::publish_to_channel(
        &state.redis,
        channel_id,
        &WsServerBody::VoiceState {
            channel_id,
            participants: briefs,
        },
    )
    .await
    {
        tracing::warn!(channel_id, "voice state publish failed: {e}");
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// ApiError has no Debug impl (error.rs is orchestrator-owned), so
    /// `Result::expect` is unavailable on ApiResult values in tests.
    fn ok<T>(r: ApiResult<T>, what: &str) -> T {
        r.unwrap_or_else(|e| panic!("{what}: expected Ok, got {:?} {}", e.status, e.message))
    }

    #[test]
    fn turn_uri_is_ice_standard() {
        assert_eq!(turn_uri("localhost:3478"), "turn:localhost:3478");
        assert_eq!(
            turn_uri("turn.example.com:3478"),
            "turn:turn.example.com:3478"
        );
    }

    /// Full live-DB integration test of join/leave/relay. Ignored by
    /// default: needs the dev postgres+redis (.env). Run with
    /// `set -a; . ./.env; set +a; cargo test -p bysyc-server voice:: -- --ignored`.
    #[ignore]
    #[tokio::test]
    async fn voice_flow_against_live_db() {
        let config = crate::config::Config::from_env();
        let pg = crate::db::connect_pool(&config.database_url, config.db_max_connections)
            .await
            .expect("pg");
        let redis_client = redis::Client::open(config.redis_url.as_str()).expect("redis url");
        let redis = redis::aio::ConnectionManager::new(redis_client.clone())
            .await
            .expect("redis");
        // A second manager, not a clone — event publishes get their own
        // pipe, mirroring boot. The S3 client is never used by this test.
        let redis_events = redis::aio::ConnectionManager::new(redis_client)
            .await
            .expect("redis events");
        let s3 = crate::s3::client(&config);
        let state = AppState {
            pg: pg.clone(),
            redis,
            redis_events,
            s3,
            config,
        };

        // Fixture: guild owned by A with text+voice channels, 7 member
        // accounts (A..G) for the cap, and a DM between A and B.
        let names: Vec<String> = (b'a'..=b'g')
            .map(|c| format!("s5_voice_{}", c as char))
            .collect();
        let mut ids = Vec::new();
        for n in &names {
            let id: i64 = sqlx::query_scalar(
                "INSERT INTO accounts(username, password_hash, identity_key) \
                 VALUES ($1, 'x', 'a2V5') RETURNING id",
            )
            .bind(n)
            .fetch_one(&pg)
            .await
            .expect("account");
            ids.push(id);
        }
        let (a, b) = (ids[0], ids[1]);
        let guild_id: i64 = sqlx::query_scalar(
            "INSERT INTO guilds(name, owner_id) VALUES ('s5-voice-test', $1) RETURNING id",
        )
        .bind(a)
        .fetch_one(&pg)
        .await
        .expect("guild");
        for id in &ids {
            sqlx::query("INSERT INTO guild_members(guild_id, account_id) VALUES ($1, $2)")
                .bind(guild_id)
                .bind(id)
                .execute(&pg)
                .await
                .expect("member");
        }
        let text_id: i64 = sqlx::query_scalar(
            "INSERT INTO channels(guild_id, kind, name) VALUES ($1, 'text', 't') RETURNING id",
        )
        .bind(guild_id)
        .fetch_one(&pg)
        .await
        .expect("text channel");
        let voice_id: i64 = sqlx::query_scalar(
            "INSERT INTO channels(guild_id, kind, name) VALUES ($1, 'voice', 'v') RETURNING id",
        )
        .bind(guild_id)
        .fetch_one(&pg)
        .await
        .expect("voice channel");
        sqlx::query("INSERT INTO friends(a, b) VALUES (LEAST($1,$2), GREATEST($1,$2))")
            .bind(a)
            .bind(b)
            .execute(&pg)
            .await
            .expect("friends");
        let dm_id: i64 = sqlx::query_scalar(
            "INSERT INTO channels(guild_id, kind, name) VALUES (NULL, 'text', '') RETURNING id",
        )
        .fetch_one(&pg)
        .await
        .expect("dm channel");
        sqlx::query(
            "INSERT INTO dm_channels(channel_id, a, b) VALUES ($1, LEAST($2,$3), GREATEST($2,$3))",
        )
        .bind(dm_id)
        .bind(a)
        .bind(b)
        .execute(&pg)
        .await
        .expect("dm pair");

        // -- text channel is not joinable
        let err = join(&state, text_id, a)
            .await
            .expect_err("text join must fail");
        assert_eq!(err.code, bysyc_common::protocol::ErrorCode::InvalidRequest);

        // -- unknown channel
        let err = join(&state, 987_654_321, a)
            .await
            .expect_err("unknown channel");
        assert_eq!(err.code, bysyc_common::protocol::ErrorCode::NotFound);

        // -- A joins, sees themselves
        let ps = ok(join(&state, voice_id, a).await, "a joins");
        assert_eq!(ps.iter().map(|p| p.id).collect::<Vec<_>>(), vec![a]);

        // -- idempotent re-join: still one row, one participant
        let ps = ok(join(&state, voice_id, a).await, "a re-joins");
        assert_eq!(ps.len(), 1);

        // -- B joins; snapshot has both, join order
        let ps = ok(join(&state, voice_id, b).await, "b joins");
        assert_eq!(ps.iter().map(|p| p.id).collect::<Vec<_>>(), vec![a, b]);

        // -- fill the channel to the cap of 6, then G is rejected
        for id in &ids[2..6] {
            ok(join(&state, voice_id, *id).await, "filler joins");
        }
        let err = join(&state, voice_id, ids[6])
            .await
            .expect_err("must be full");
        assert_eq!(
            err.code,
            bysyc_common::protocol::ErrorCode::VoiceChannelFull
        );
        assert_eq!(err.status, axum::http::StatusCode::CONFLICT);

        // -- relay within the voice call: both participants OK
        ok(
            relay_signal(&state, voice_id, a, b, CallSignalKind::Hangup).await,
            "relay between participants",
        );
        // someone outside the call is not relayed to
        let err = relay_signal(&state, voice_id, ids[6], a, CallSignalKind::Hangup)
            .await
            .expect_err("outsider cannot relay");
        assert_eq!(err.code, bysyc_common::protocol::ErrorCode::Forbidden);

        // -- leave frees a slot; G can now join
        ok(leave(&state, voice_id, a).await, "a leaves");
        ok(
            join(&state, voice_id, ids[6]).await,
            "g joins after slot freed",
        );
        // not-in-channel leave is a no-op success
        ok(leave(&state, voice_id, a).await, "leave while absent");

        // -- Private Call signaling in the DM: exact pair only
        ok(
            relay_signal(&state, dm_id, a, b, CallSignalKind::Hangup).await,
            "dm pair relay",
        );
        ok(
            relay_signal(&state, dm_id, b, a, CallSignalKind::Hangup).await,
            "dm pair relay, reverse direction",
        );
        let err = relay_signal(&state, dm_id, a, ids[2], CallSignalKind::Hangup)
            .await
            .expect_err("non-pair cannot relay in dm");
        assert_eq!(err.code, bysyc_common::protocol::ErrorCode::Forbidden);

        // Teardown: accounts cascade guild/membership/participants; friends
        // and the dm channel reference the same accounts.
        sqlx::query("DELETE FROM guilds WHERE id = $1")
            .bind(guild_id)
            .execute(&pg)
            .await
            .unwrap();
        sqlx::query("DELETE FROM channels WHERE id = $1")
            .bind(dm_id)
            .execute(&pg)
            .await
            .unwrap();
        for n in &names {
            sqlx::query("DELETE FROM accounts WHERE username = $1")
                .bind(n)
                .execute(&pg)
                .await
                .unwrap();
        }
    }
}
