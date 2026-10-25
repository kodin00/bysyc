//! Guild, Channel, Guild Invite and DM endpoints.
//!
//! House conventions (mirrors friends.rs / auth.rs):
//! - `Authed` comes from [`crate::session`]; every handler requires it.
//! - DB timestamps are TIMESTAMPTZ; unix-ms conversion happens in SQL via
//!   `(EXTRACT(EPOCH FROM ts) * 1000)::bigint`, and expiry arithmetic runs
//!   DB-side (`now() + interval`) so no clock skew creeps in.
//! - `friends` / `dm_channels` pairs are stored normalized (`a < b`);
//!   queries use LEAST/GREATEST.
//! - WS events fan out once the mutation has landed; the guild member
//!   fan-out goes through [`crate::events`] — one serialized payload, one
//!   pipelined Redis round trip.
//!
//! Semantics pinned for v1:
//! - Channel create/delete and invite issuance are Owner-only; anyone else
//!   (Member or not) gets `Forbidden`.
//! - An Owner may leave their own Guild; the Guild then persists ownerless
//!   (no ownership transfer or dissolution exists in v1).
//! - Deleting a Channel cascades its Messages via FK.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{delete, post};
use axum::{Json, Router};
use bysyc_common::protocol::{
    AccountBrief, ChannelInfo, ChannelKind, CreateChannelRequest, CreateGuildInviteRequest,
    CreateGuildRequest, DmChannel, ErrorCode, GuildInfo, GuildInviteDto, JoinGuildRequest,
    OpenDmRequest, WsServerBody,
};
use rand::distr::{Alphanumeric, SampleString};

use crate::db::AppState;
use crate::error::{ApiError, ApiResult};
use crate::events;
use crate::s3;
use crate::session::Authed;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/guilds", post(create_guild).get(list_guilds))
        .route("/guilds/join", post(join_guild))
        .route("/guilds/{guild_id}/channels", post(create_channel))
        .route("/guilds/{guild_id}/invites", post(create_invite))
        .route("/guilds/{guild_id}/leave", post(leave_guild))
        .route("/channels/{channel_id}", delete(delete_channel))
        .route("/dms", post(open_dm).get(list_dms))
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

/// Guild Invite code: 22 chars of `[a-zA-Z0-9]` (~130 bits).
fn invite_code() -> String {
    Alphanumeric.sample_string(&mut rand::rng(), 22)
}

fn kind_str(kind: &ChannelKind) -> &'static str {
    match kind {
        ChannelKind::Text => "text",
        ChannelKind::Voice => "voice",
        ChannelKind::Dm => "dm",
    }
}

fn parse_kind(kind: &str) -> ApiResult<ChannelKind> {
    match kind {
        "text" => Ok(ChannelKind::Text),
        "voice" => Ok(ChannelKind::Voice),
        "dm" => Ok(ChannelKind::Dm),
        other => {
            tracing::error!("unknown channel kind in db: {other}");
            Err(ApiError::internal("database error"))
        }
    }
}

/// (id, username, identity_key)
type BriefRow = (i64, String, Option<String>);

const BRIEF_SQL: &str = "SELECT id, username, identity_key FROM accounts WHERE id = $1";

/// Online = `EXISTS presence:{id}` (the WS gateway maintains those keys).
async fn is_online(state: &AppState, id: i64) -> ApiResult<bool> {
    let mut conn = state.redis.clone();
    Ok(redis::cmd("EXISTS")
        .arg(format!("presence:{id}"))
        .query_async(&mut conn)
        .await?)
}

/// The Guild's owner id, or `None` when the Guild does not exist.
async fn guild_owner(pool: &sqlx::PgPool, guild_id: i64) -> ApiResult<Option<i64>> {
    Ok(
        sqlx::query_scalar("SELECT owner_id FROM guilds WHERE id = $1")
            .bind(guild_id)
            .fetch_optional(pool)
            .await?,
    )
}

/// The Guild must exist (else `NotFound`) and be owned by `me` (else
/// `Forbidden`).
async fn require_owner(pool: &sqlx::PgPool, guild_id: i64, me: i64) -> ApiResult<()> {
    let owner = guild_owner(pool, guild_id)
        .await?
        .ok_or_else(|| ApiError::not_found("no such guild"))?;
    if owner != me {
        return Err(ApiError::forbidden("only the guild owner may do this"));
    }
    Ok(())
}

async fn member_ids(pool: &sqlx::PgPool, guild_id: i64) -> ApiResult<Vec<i64>> {
    Ok(
        sqlx::query_scalar("SELECT account_id FROM guild_members WHERE guild_id = $1")
            .bind(guild_id)
            .fetch_all(pool)
            .await?,
    )
}

/// Full GuildInfo snapshot (guild row + channels ordered by id) in one
/// `guilds LEFT JOIN channels` query — the same shape list_guilds folds.
async fn guild_info(pool: &sqlx::PgPool, guild_id: i64) -> ApiResult<GuildInfo> {
    // (guild name, owner id, channel id, channel kind, channel name): one row
    // per channel, plus a single all-NULL channel row for an empty guild.
    type Row = (String, i64, Option<i64>, Option<String>, Option<String>);
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT g.name, g.owner_id, c.id, c.kind, c.name \
         FROM guilds g LEFT JOIN channels c ON c.guild_id = g.id \
         WHERE g.id = $1 ORDER BY c.id",
    )
    .bind(guild_id)
    .fetch_all(pool)
    .await?;
    // A guild with no channels still yields one row of NULL channel
    // columns; no rows at all means the guild does not exist.
    let (name, owner_id) = match rows.first() {
        Some((name, owner_id, ..)) => (name.clone(), *owner_id),
        None => return Err(ApiError::not_found("no such guild")),
    };
    let mut channels = Vec::new();
    for (_, _, id, kind, ch_name) in rows {
        if let (Some(id), Some(kind), Some(ch_name)) = (id, kind, ch_name) {
            channels.push(ChannelInfo {
                id,
                guild_id: Some(guild_id),
                kind: parse_kind(&kind)?,
                name: ch_name,
            });
        }
    }
    Ok(GuildInfo {
        id: guild_id,
        name,
        owner_id,
        channels,
    })
}

// ---------------------------------------------------------------------------
// Guilds
// ---------------------------------------------------------------------------

async fn create_guild(
    State(state): State<AppState>,
    Authed(me): Authed,
    Json(req): Json<CreateGuildRequest>,
) -> ApiResult<Json<GuildInfo>> {
    let mut tx = state.pg.begin().await?;
    let (guild_id,): (i64,) =
        sqlx::query_as("INSERT INTO guilds (name, owner_id) VALUES ($1, $2) RETURNING id")
            .bind(&req.name)
            .bind(me)
            .fetch_one(&mut *tx)
            .await?;
    sqlx::query("INSERT INTO guild_members (guild_id, account_id) VALUES ($1, $2)")
        .bind(guild_id)
        .bind(me)
        .execute(&mut *tx)
        .await?;
    // Two default Channels. Names may repeat across kinds — `name` is not
    // unique. Serial order gives text the lower id, so id-sorted channels
    // come out text-then-voice, matching guild_info()/list_guilds().
    let (text_id,): (i64,) = sqlx::query_as(
        "INSERT INTO channels (guild_id, kind, name) VALUES ($1, 'text', 'general') RETURNING id",
    )
    .bind(guild_id)
    .fetch_one(&mut *tx)
    .await?;
    let (voice_id,): (i64,) = sqlx::query_as(
        "INSERT INTO channels (guild_id, kind, name) VALUES ($1, 'voice', 'general') RETURNING id",
    )
    .bind(guild_id)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    tracing::info!(guild_id, owner_id = me, "guild created");

    Ok(Json(GuildInfo {
        id: guild_id,
        name: req.name,
        owner_id: me,
        channels: vec![
            ChannelInfo {
                id: text_id,
                guild_id: Some(guild_id),
                kind: ChannelKind::Text,
                name: "general".into(),
            },
            ChannelInfo {
                id: voice_id,
                guild_id: Some(guild_id),
                kind: ChannelKind::Voice,
                name: "general".into(),
            },
        ],
    }))
}

/// One row of the guild x channel outer join; channel columns are NULL when
/// the guild has no channels.
type GuildListRow = (
    i64,
    String,
    i64,
    Option<i64>,
    Option<String>,
    Option<String>,
);

async fn list_guilds(
    State(state): State<AppState>,
    Authed(me): Authed,
) -> ApiResult<Json<Vec<GuildInfo>>> {
    let rows: Vec<GuildListRow> = sqlx::query_as(
        "SELECT g.id, g.name, g.owner_id, c.id, c.kind, c.name \
         FROM guild_members m \
         JOIN guilds g ON g.id = m.guild_id \
         LEFT JOIN channels c ON c.guild_id = g.id \
         WHERE m.account_id = $1 \
         ORDER BY g.id, c.id",
    )
    .bind(me)
    .fetch_all(&state.pg)
    .await?;

    // Rows arrive grouped by g.id (ordered), so fold into Vec<GuildInfo>.
    let mut guilds: Vec<GuildInfo> = Vec::new();
    for (gid, name, owner_id, channel_id, kind, channel_name) in rows {
        let is_last = guilds.last().is_some_and(|g| g.id == gid);
        let guild = if is_last {
            guilds.last_mut().expect("non-empty by is_last")
        } else {
            guilds.push(GuildInfo {
                id: gid,
                name,
                owner_id,
                channels: Vec::new(),
            });
            guilds.last_mut().expect("just pushed")
        };
        if let (Some(id), Some(kind), Some(ch_name)) = (channel_id, kind, channel_name) {
            guild.channels.push(ChannelInfo {
                id,
                guild_id: Some(gid),
                kind: parse_kind(&kind)?,
                name: ch_name,
            });
        }
    }
    Ok(Json(guilds))
}

async fn join_guild(
    State(state): State<AppState>,
    Authed(me): Authed,
    Json(req): Json<JoinGuildRequest>,
) -> ApiResult<Json<GuildInfo>> {
    // One query resolves the invite's guild, whether we are already a
    // member (idempotent rejoin), and our own brief columns for the
    // MemberJoined fan-out below.
    let lookup: Option<(i64, bool, String, Option<String>)> = sqlx::query_as(
        "SELECT i.guild_id, \
                EXISTS(SELECT 1 FROM guild_members m \
                       WHERE m.guild_id = i.guild_id AND m.account_id = $2), \
                a.username, a.identity_key \
         FROM guild_invites i JOIN accounts a ON a.id = $2 \
         WHERE i.code = $1",
    )
    .bind(&req.code)
    .bind(me)
    .fetch_optional(&state.pg)
    .await?;
    let Some((guild_id, already_member, username, identity_key)) = lookup else {
        return Err(ApiError::bad(
            ErrorCode::InvalidInvite,
            "unknown invite code",
        ));
    };

    // Idempotent: joining a Guild already joined just returns it (no use
    // consumed, no events).
    if already_member {
        return Ok(Json(guild_info(&state.pg, guild_id).await?));
    }

    // Consume one use, record the membership and list the members from
    // before this join — one atomic statement, so the WHERE clause
    // re-validates expiry and the use limit and concurrent redemptions
    // cannot overshoot max_uses. An expired or used-up invite leaves
    // `consume` (and with it the whole result set) empty.
    // A concurrent join by the same account lands on the PK; treat as the
    // same successful join rather than an error.
    let rows: Vec<(i64, Option<i64>)> = sqlx::query_as(
        "WITH consume AS ( \
             UPDATE guild_invites SET uses = uses + 1 \
             WHERE code = $1 AND (expires_at IS NULL OR expires_at > now()) \
               AND (max_uses IS NULL OR uses < max_uses) \
             RETURNING guild_id \
         ), joined AS ( \
             INSERT INTO guild_members (guild_id, account_id) \
             SELECT guild_id, $2 FROM consume ON CONFLICT DO NOTHING \
         ) \
         SELECT c.guild_id, m.account_id \
         FROM consume c LEFT JOIN guild_members m \
              ON m.guild_id = c.guild_id AND m.account_id <> $2",
    )
    .bind(&req.code)
    .bind(me)
    .fetch_all(&state.pg)
    .await?;
    if rows.is_empty() {
        return Err(ApiError::bad(
            ErrorCode::InvalidInvite,
            "invite code expired or used up",
        ));
    }
    let existing: Vec<i64> = rows.iter().filter_map(|&(_, member)| member).collect();

    // The snapshot and our presence probe are independent; run them
    // concurrently.
    let (guild, online) = tokio::join!(guild_info(&state.pg, guild_id), is_online(&state, me));
    let guild = guild?;
    let my_brief = AccountBrief {
        id: me,
        username,
        identity_key: identity_key.unwrap_or_default(),
        online: online?,
    };

    // Members from *before* this join get MemberJoined; I get GuildJoined —
    // one batch, one round trip, each payload serialized once.
    events::FanOut::new()
        .accounts(
            &existing,
            WsServerBody::MemberJoined {
                guild_id,
                account: my_brief,
            },
        )
        .account(
            me,
            WsServerBody::GuildJoined {
                guild: guild.clone(),
            },
        )
        .flush(&state.redis_events)
        .await?;
    tracing::info!(guild_id, account_id = me, "guild joined");
    Ok(Json(guild))
}

async fn leave_guild(
    State(state): State<AppState>,
    Authed(me): Authed,
    Path(guild_id): Path<i64>,
) -> ApiResult<StatusCode> {
    guild_owner(&state.pg, guild_id)
        .await?
        .ok_or_else(|| ApiError::not_found("no such guild"))?;

    let mut tx = state.pg.begin().await?;
    // v1: the Owner may leave too — the Guild then persists ownerless (no
    // ownership transfer or dissolution flow exists yet).
    let deleted = sqlx::query("DELETE FROM guild_members WHERE guild_id = $1 AND account_id = $2")
        .bind(guild_id)
        .bind(me)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    if deleted == 0 {
        return Err(ApiError::not_found("not a member of this guild"));
    }
    let remaining: Vec<i64> =
        sqlx::query_scalar("SELECT account_id FROM guild_members WHERE guild_id = $1")
            .bind(guild_id)
            .fetch_all(&mut *tx)
            .await?;
    tx.commit().await?;

    events::publish_to_accounts(
        &state.redis_events,
        &remaining,
        WsServerBody::MemberLeft {
            guild_id,
            account_id: me,
        },
    )
    .await?;
    tracing::info!(guild_id, account_id = me, "guild left");
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// Channels
// ---------------------------------------------------------------------------

async fn create_channel(
    State(state): State<AppState>,
    Authed(me): Authed,
    Path(guild_id): Path<i64>,
    Json(req): Json<CreateChannelRequest>,
) -> ApiResult<Json<ChannelInfo>> {
    if matches!(req.kind, ChannelKind::Dm) {
        return Err(ApiError::invalid(
            "dm channels are server-created via POST /dms, not here",
        ));
    }
    require_owner(&state.pg, guild_id, me).await?;

    let (channel_id,): (i64,) = sqlx::query_as(
        "INSERT INTO channels (guild_id, kind, name) VALUES ($1, $2, $3) RETURNING id",
    )
    .bind(guild_id)
    .bind(kind_str(&req.kind))
    .bind(&req.name)
    .fetch_one(&state.pg)
    .await?;
    let channel = ChannelInfo {
        id: channel_id,
        guild_id: Some(guild_id),
        kind: req.kind,
        name: req.name,
    };
    events::publish_to_accounts(
        &state.redis_events,
        &member_ids(&state.pg, guild_id).await?,
        WsServerBody::ChannelCreated {
            guild_id,
            channel: channel.clone(),
        },
    )
    .await?;
    tracing::info!(guild_id, channel_id, owner_id = me, "channel created");
    Ok(Json(channel))
}

async fn delete_channel(
    State(state): State<AppState>,
    Authed(me): Authed,
    Path(channel_id): Path<i64>,
) -> ApiResult<StatusCode> {
    // fetch_optional gives Option<Option<i64>>: outer None = no such channel
    // row, inner None = a DM channel (guild_id NULL) — neither is deletable
    // here.
    let guild_id: Option<i64> = sqlx::query_scalar("SELECT guild_id FROM channels WHERE id = $1")
        .bind(channel_id)
        .fetch_optional(&state.pg)
        .await?
        .flatten();
    let guild_id = guild_id.ok_or_else(|| ApiError::not_found("no such channel"))?;

    require_owner(&state.pg, guild_id, me).await?;

    // Collect S3 keys before the cascade: DELETE FROM channels cascades
    // messages (and ON DELETE SET NULL severs the attachments' link) but
    // never removes the S3 objects, so we best-effort delete them after.
    let keys: Vec<String> = sqlx::query_scalar(
        "SELECT s3_key FROM attachments \
         WHERE message_id IN (SELECT id FROM messages WHERE channel_id = $1)",
    )
    .bind(channel_id)
    .fetch_all(&state.pg)
    .await?;

    sqlx::query("DELETE FROM channels WHERE id = $1")
        .bind(channel_id)
        .execute(&state.pg)
        .await?;

    // Best-effort object removal: the rows are gone (or their message
    // links NULL), so a leftover object behind an unguessable key is the
    // only consequence of a failure here. Never fail the request.
    for key in &keys {
        let key = key.as_str();
        if let Err(e) = s3::delete_object(&state, key).await {
            tracing::warn!(
                channel_id,
                key,
                "channel deleted but object removal failed: {}",
                e.message
            );
        }
    }

    events::publish_to_accounts(
        &state.redis_events,
        &member_ids(&state.pg, guild_id).await?,
        WsServerBody::ChannelDeleted {
            guild_id,
            channel_id,
        },
    )
    .await?;
    tracing::info!(guild_id, channel_id, owner_id = me, "channel deleted");
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// Invites
// ---------------------------------------------------------------------------

async fn create_invite(
    State(state): State<AppState>,
    Authed(me): Authed,
    Path(guild_id): Path<i64>,
    Json(req): Json<CreateGuildInviteRequest>,
) -> ApiResult<Json<GuildInviteDto>> {
    require_owner(&state.pg, guild_id, me).await?;

    let code = invite_code();
    // Expiry is computed DB-side from now() so it agrees exactly with the
    // `expires_at > now()` redemption check; a NULL ttl writes NULL because
    // `interval * NULL` is NULL.
    let (expires_at_ms,): (Option<i64>,) = sqlx::query_as(
        "INSERT INTO guild_invites (code, guild_id, created_by, max_uses, uses, expires_at) \
         VALUES ($1, $2, $3, $4, 0, now() + (interval '1 second' * $5)) \
         RETURNING (EXTRACT(EPOCH FROM expires_at) * 1000)::bigint",
    )
    .bind(&code)
    .bind(guild_id)
    .bind(me)
    .bind(req.max_uses)
    .bind(req.ttl_secs)
    .fetch_one(&state.pg)
    .await?;
    tracing::info!(guild_id, code = %code, "guild invite issued");

    Ok(Json(GuildInviteDto {
        code,
        guild_id,
        max_uses: req.max_uses,
        uses: 0,
        expires_at_ms,
    }))
}

// ---------------------------------------------------------------------------
// DMs
// ---------------------------------------------------------------------------

async fn open_dm(
    State(state): State<AppState>,
    Authed(me): Authed,
    Json(req): Json<OpenDmRequest>,
) -> ApiResult<Json<DmChannel>> {
    let peer: Option<BriefRow> = sqlx::query_as(BRIEF_SQL)
        .bind(req.account_id)
        .fetch_optional(&state.pg)
        .await?;
    let (peer_id, peer_username, peer_identity_key) =
        peer.ok_or_else(|| ApiError::not_found("no such account"))?;

    // DMs require an accepted friendship (stored normalized: a < b). A
    // self-DM can never match (CHECK(a < b)), so it lands here too.
    let friend: Option<i64> = sqlx::query_scalar(
        "SELECT a FROM friends WHERE a = LEAST($1, $2) AND b = GREATEST($1, $2)",
    )
    .bind(me)
    .bind(peer_id)
    .fetch_optional(&state.pg)
    .await?;
    if friend.is_none() {
        return Err(ApiError::forbidden("DMs require an accepted friend"));
    }

    let (a, b) = (me.min(peer_id), me.max(peer_id));
    let channel_id = find_or_create_dm(&state.pg, a, b).await?;

    let dm_peer = AccountBrief {
        id: peer_id,
        online: is_online(&state, peer_id).await?,
        username: peer_username,
        identity_key: peer_identity_key.unwrap_or_default(),
    };
    Ok(Json(DmChannel {
        // DM channels are always reported as kind Dm with the peer's
        // username as the synthesized name; the backing channels row is
        // guild_id NULL, kind 'text'.
        channel: ChannelInfo {
            id: channel_id,
            guild_id: None,
            kind: ChannelKind::Dm,
            name: dm_peer.username.clone(),
        },
        peer: dm_peer,
    }))
}

/// Idempotent DM lookup: reuse the pair's existing channel, else create the
/// channels row (guild_id NULL, kind 'text') plus the dm_channels row in one
/// transaction. A concurrent opener that wins on UNIQUE(a,b) makes our
/// surplus channels row roll back and their channel id is used instead.
async fn find_or_create_dm(pool: &sqlx::PgPool, a: i64, b: i64) -> ApiResult<i64> {
    let mut tx = pool.begin().await?;
    let existing: Option<i64> =
        sqlx::query_scalar("SELECT channel_id FROM dm_channels WHERE a = $1 AND b = $2")
            .bind(a)
            .bind(b)
            .fetch_optional(&mut *tx)
            .await?;
    if let Some(channel_id) = existing {
        return Ok(channel_id); // tx drops with nothing written
    }

    let (channel_id,): (i64,) = sqlx::query_as(
        "INSERT INTO channels (guild_id, kind, name) VALUES (NULL, 'text', '') RETURNING id",
    )
    .fetch_one(&mut *tx)
    .await?;
    let inserted = sqlx::query(
        "INSERT INTO dm_channels (channel_id, a, b) VALUES ($1, $2, $3) \
         ON CONFLICT (a, b) DO NOTHING",
    )
    .bind(channel_id)
    .bind(a)
    .bind(b)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if inserted == 0 {
        // Lost the race: discard our channels row, use the winner's.
        tx.rollback().await?;
        let winner: i64 =
            sqlx::query_scalar("SELECT channel_id FROM dm_channels WHERE a = $1 AND b = $2")
                .bind(a)
                .bind(b)
                .fetch_one(pool)
                .await?;
        return Ok(winner);
    }
    tx.commit().await?;
    Ok(channel_id)
}

/// (channel_id, peer_id, peer_username, peer_identity_key)
type DmListRow = (i64, i64, String, Option<String>);

async fn list_dms(
    State(state): State<AppState>,
    Authed(me): Authed,
) -> ApiResult<Json<Vec<DmChannel>>> {
    let rows: Vec<DmListRow> = sqlx::query_as(
        "SELECT m.channel_id, p.id, p.username, p.identity_key \
         FROM dm_channels m \
         JOIN accounts p ON p.id = CASE WHEN m.a = $1 THEN m.b ELSE m.a END \
         WHERE m.a = $1 OR m.b = $1 \
         ORDER BY m.channel_id DESC",
    )
    .bind(me)
    .fetch_all(&state.pg)
    .await?;

    if rows.is_empty() {
        return Ok(Json(Vec::new()));
    }
    // One pipeline of presence probes for the whole list.
    let mut pipe = redis::Pipeline::new();
    for (_, peer_id, _, _) in &rows {
        pipe.cmd("EXISTS").arg(format!("presence:{peer_id}"));
    }
    let mut conn = state.redis.clone();
    let online: Vec<bool> = pipe.query_async(&mut conn).await?;

    let dms = rows
        .into_iter()
        .zip(online)
        .map(
            |((channel_id, peer_id, username, identity_key), online)| DmChannel {
                channel: ChannelInfo {
                    id: channel_id,
                    guild_id: None,
                    kind: ChannelKind::Dm,
                    name: username.clone(),
                },
                peer: AccountBrief {
                    id: peer_id,
                    username,
                    identity_key: identity_key.unwrap_or_default(),
                    online,
                },
            },
        )
        .collect();
    Ok(Json(dms))
}
