//! Guild, Channel, Guild Invite and DM endpoints.
//!
//! House conventions (mirrors friends.rs / auth.rs):
//! - `Authed` comes from [`crate::session`]; every handler requires it.
//! - DB timestamps are TIMESTAMPTZ; unix-ms conversion happens in SQL via
//!   `(EXTRACT(EPOCH FROM ts) * 1000)::bigint`, and expiry arithmetic runs
//!   DB-side (`now() + interval`) so no clock skew creeps in.
//! - `friends` / `dm_channels` pairs are stored normalized (`a < b`);
//!   queries use LEAST/GREATEST.
//! - WS events fan out through [`crate::events::publish_to_account`] after
//!   the mutating transaction has committed.
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
        other => Err(ApiError::internal(format!(
            "unknown channel kind in db: {other}"
        ))),
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

async fn guild_channels(pool: &sqlx::PgPool, guild_id: i64) -> ApiResult<Vec<ChannelInfo>> {
    let rows: Vec<(i64, String, String)> =
        sqlx::query_as("SELECT id, kind, name FROM channels WHERE guild_id = $1 ORDER BY id")
            .bind(guild_id)
            .fetch_all(pool)
            .await?;
    rows.into_iter()
        .map(|(id, kind, name)| {
            Ok(ChannelInfo {
                id,
                guild_id: Some(guild_id),
                kind: parse_kind(&kind)?,
                name,
            })
        })
        .collect()
}

/// Full GuildInfo snapshot (guild row + channels ordered by id).
async fn guild_info(pool: &sqlx::PgPool, guild_id: i64) -> ApiResult<GuildInfo> {
    let (name, owner_id): (String, i64) =
        sqlx::query_as("SELECT name, owner_id FROM guilds WHERE id = $1")
            .bind(guild_id)
            .fetch_optional(pool)
            .await?
            .ok_or_else(|| ApiError::not_found("no such guild"))?;
    Ok(GuildInfo {
        id: guild_id,
        name,
        owner_id,
        channels: guild_channels(pool, guild_id).await?,
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
    // come out text-then-voice, matching guild_channels().
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
    let guild_id: Option<i64> =
        sqlx::query_scalar("SELECT guild_id FROM guild_invites WHERE code = $1")
            .bind(&req.code)
            .fetch_optional(&state.pg)
            .await?;
    let Some(guild_id) = guild_id else {
        return Err(ApiError::bad(
            ErrorCode::InvalidInvite,
            "unknown invite code",
        ));
    };

    // Idempotent: joining a Guild already joined just returns it (no use
    // consumed, no events).
    let member: Option<i64> = sqlx::query_scalar(
        "SELECT account_id FROM guild_members WHERE guild_id = $1 AND account_id = $2",
    )
    .bind(guild_id)
    .bind(me)
    .fetch_optional(&state.pg)
    .await?;
    if member.is_some() {
        return Ok(Json(guild_info(&state.pg, guild_id).await?));
    }

    let mut tx = state.pg.begin().await?;
    // Consume one use atomically; the WHERE clause re-validates expiry and
    // the use limit so concurrent redemptions cannot overshoot max_uses.
    let consumed = sqlx::query(
        "UPDATE guild_invites SET uses = uses + 1 \
         WHERE code = $1 AND (expires_at IS NULL OR expires_at > now()) \
           AND (max_uses IS NULL OR uses < max_uses)",
    )
    .bind(&req.code)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if consumed == 0 {
        return Err(ApiError::bad(
            ErrorCode::InvalidInvite,
            "invite code expired or used up",
        ));
    }
    // A concurrent join by the same account lands on the PK; treat as the
    // same successful join rather than an error.
    sqlx::query(
        "INSERT INTO guild_members (guild_id, account_id) VALUES ($1, $2) \
         ON CONFLICT DO NOTHING",
    )
    .bind(guild_id)
    .bind(me)
    .execute(&mut *tx)
    .await?;
    // Members from *before* this join get MemberJoined; I get GuildJoined.
    let existing: Vec<i64> = sqlx::query_scalar(
        "SELECT account_id FROM guild_members WHERE guild_id = $1 AND account_id <> $2",
    )
    .bind(guild_id)
    .bind(me)
    .fetch_all(&mut *tx)
    .await?;
    let my_row: BriefRow = sqlx::query_as(BRIEF_SQL)
        .bind(me)
        .fetch_one(&mut *tx)
        .await?;
    tx.commit().await?;

    let my_brief = AccountBrief {
        id: my_row.0,
        username: my_row.1,
        identity_key: my_row.2.unwrap_or_default(),
        online: is_online(&state, me).await?,
    };
    for member in existing {
        events::publish_to_account(
            &state.redis,
            member,
            &WsServerBody::MemberJoined {
                guild_id,
                account: my_brief.clone(),
            },
        )
        .await?;
    }
    let guild = guild_info(&state.pg, guild_id).await?;
    events::publish_to_account(
        &state.redis,
        me,
        &WsServerBody::GuildJoined {
            guild: guild.clone(),
        },
    )
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

    for member in remaining {
        events::publish_to_account(
            &state.redis,
            member,
            &WsServerBody::MemberLeft {
                guild_id,
                account_id: me,
            },
        )
        .await?;
    }
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
    for member in member_ids(&state.pg, guild_id).await? {
        events::publish_to_account(
            &state.redis,
            member,
            &WsServerBody::ChannelCreated {
                guild_id,
                channel: channel.clone(),
            },
        )
        .await?;
    }
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
    // Messages cascade via FK; attachments' message links become NULL.
    sqlx::query("DELETE FROM channels WHERE id = $1")
        .bind(channel_id)
        .execute(&state.pg)
        .await?;
    for member in member_ids(&state.pg, guild_id).await? {
        events::publish_to_account(
            &state.redis,
            member,
            &WsServerBody::ChannelDeleted {
                guild_id,
                channel_id,
            },
        )
        .await?;
    }
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
         JOIN channels c ON c.id = m.channel_id \
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
