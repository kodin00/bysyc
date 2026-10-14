//! Local persistence: SQLite (rusqlite, bundled) for the world cache and
//! message history, plus the OS keychain for the session token.
//!
//! All methods take `&self`; the whole [`Store`] is shared as
//! `Arc<Mutex<Store>>` and locked briefly from the UI and network threads.
//! Message rows carry a `plaintext` column that stays `NULL` until C2/C3
//! decrypt and fill it via [`Store::set_plaintext`].

use std::path::Path;

use bysyc_common::protocol::{
    AccountBrief, AttachmentMeta, ChannelInfo, DmChannel, GuildInfo, MessageDto, MessageKind,
};
use rusqlite::{Connection, OptionalExtension, params};

use crate::state::guard;

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS settings(
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS keys(
    scope  TEXT PRIMARY KEY,
    pickle BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS messages(
    id             INTEGER PRIMARY KEY,
    channel_id     INTEGER NOT NULL,
    sender_id      INTEGER NOT NULL,
    kind           TEXT NOT NULL,
    content        TEXT NOT NULL,
    reply_to       INTEGER NULL,
    attachment_json TEXT NULL,
    created_at_ms  INTEGER NOT NULL,
    plaintext      TEXT NULL
);
CREATE INDEX IF NOT EXISTS idx_messages_channel ON messages(channel_id);
CREATE TABLE IF NOT EXISTS friends(
    id           INTEGER PRIMARY KEY,
    username     TEXT NOT NULL,
    identity_key TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS guilds(
    id       INTEGER PRIMARY KEY,
    name     TEXT NOT NULL,
    owner_id INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS channels(
    id       INTEGER PRIMARY KEY,
    guild_id INTEGER NOT NULL,
    kind     TEXT NOT NULL,
    name     TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS dm(
    channel_id INTEGER PRIMARY KEY,
    peer_id    INTEGER NOT NULL
);
";

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

pub struct Store {
    conn: Connection,
}

impl Store {
    /// Open (and migrate) the store in the platform data dir
    /// (`ProjectDirs::from("", "", "bysyc")` → `data_dir/bysyc.db`).
    pub fn open_default() -> Result<Self, String> {
        let dir = directories::ProjectDirs::from("", "", "bysyc")
            .map(|d| d.data_dir().to_path_buf())
            .ok_or("cannot determine the platform data directory")?;
        std::fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
        Self::open(&dir.join("bysyc.db"))
    }

    /// Open (and migrate) the store at an explicit path.
    pub fn open(path: &Path) -> Result<Self, String> {
        let conn = Connection::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
        conn.execute_batch(SCHEMA)
            .map_err(|e| format!("migrate {}: {e}", path.display()))?;
        Ok(Store { conn })
    }

    // -- settings ----------------------------------------------------------

    pub fn setting(&self, key: &str) -> Option<String> {
        self.conn
            .query_row(
                "SELECT value FROM settings WHERE key = ?1",
                params![key],
                |r| r.get(0),
            )
            .optional()
            .ok()
            .flatten()
    }

    pub fn set_setting(&self, key: &str, value: &str) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT INTO settings(key, value) VALUES(?1, ?2)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                params![key, value],
            )
            .map_err(|e| format!("settings: {e}"))?;
        Ok(())
    }

    pub fn del_setting(&self, key: &str) -> Result<(), String> {
        self.conn
            .execute("DELETE FROM settings WHERE key = ?1", params![key])
            .map_err(|e| format!("settings: {e}"))?;
        Ok(())
    }

    // -- pickles (C2: generic encrypted-key-pickle store) --------------------

    /// Load the pickled blob stored under `scope` (e.g. an account-scoped
    /// pickle name C2 chooses).
    pub fn pickle(&self, scope: &str) -> Option<Vec<u8>> {
        self.conn
            .query_row(
                "SELECT pickle FROM keys WHERE scope = ?1",
                params![scope],
                |r| r.get(0),
            )
            .optional()
            .ok()
            .flatten()
    }

    pub fn put_pickle(&self, scope: &str, pickle: &[u8]) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT INTO keys(scope, pickle) VALUES(?1, ?2)
                 ON CONFLICT(scope) DO UPDATE SET pickle = excluded.pickle",
                params![scope, pickle],
            )
            .map_err(|e| format!("keys: {e}"))?;
        Ok(())
    }

    pub fn del_pickle(&self, scope: &str) -> Result<(), String> {
        self.conn
            .execute("DELETE FROM keys WHERE scope = ?1", params![scope])
            .map_err(|e| format!("keys: {e}"))?;
        Ok(())
    }

    // -- messages --------------------------------------------------------------

    /// Persist a server-confirmed message (optimistic temps are never
    /// persisted). Re-inserting the same id is a no-op.
    pub fn append_message(&self, m: &MessageDto) -> Result<(), String> {
        let attachment_json = match &m.attachment {
            Some(a) => Some(serde_json::to_string(a).unwrap_or_default()),
            None => None,
        };
        self.conn
            .execute(
                "INSERT OR IGNORE INTO messages(
                    id, channel_id, sender_id, kind, content, reply_to,
                    attachment_json, created_at_ms, plaintext)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,NULL)",
                params![
                    m.id,
                    m.channel_id,
                    m.sender_id,
                    kind_str(&m.kind),
                    m.content,
                    m.reply_to,
                    attachment_json,
                    m.created_at_ms,
                ],
            )
            .map_err(|e| format!("messages: {e}"))?;
        Ok(())
    }

    /// One page of cached history, newest last. `before` pages older than
    /// the given message id (mirrors the REST paging).
    pub fn messages_for(
        &self,
        channel_id: i64,
        before: Option<i64>,
        limit: u32,
    ) -> Vec<MessageDto> {
        let mut stmt = match self.conn.prepare(
            "SELECT id, channel_id, sender_id, kind, content, reply_to,
                    attachment_json, created_at_ms
             FROM messages
             WHERE channel_id = ?1 AND (?2 IS NULL OR id < ?2)
             ORDER BY id DESC
             LIMIT ?3",
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let rows = match stmt.query_map(params![channel_id, before, limit], |r| {
            let kind: String = r.get(3)?;
            let attachment_json: Option<String> = r.get(6)?;
            Ok(MessageDto {
                id: r.get(0)?,
                channel_id: r.get(1)?,
                sender_id: r.get(2)?,
                kind: parse_kind(&kind),
                content: r.get(4)?,
                reply_to: r.get(5)?,
                attachment: attachment_json
                    .and_then(|j| serde_json::from_str::<AttachmentMeta>(&j).ok()),
                created_at_ms: r.get(7)?,
            })
        }) {
            Ok(rows) => rows,
            Err(_) => return Vec::new(),
        };
        let mut out: Vec<MessageDto> = rows.filter_map(|r| r.ok()).collect();
        out.reverse(); // query is DESC (newest first) → newest last
        out
    }

    /// Fill in the decrypted plaintext for a message (C2/C3 call this).
    pub fn set_plaintext(&self, msg_id: i64, text: &str) -> Result<(), String> {
        self.conn
            .execute(
                "UPDATE messages SET plaintext = ?2 WHERE id = ?1",
                params![msg_id, text],
            )
            .map_err(|e| format!("messages: {e}"))?;
        Ok(())
    }

    /// The decrypted plaintext of a message, if any (C3 renders from this).
    pub fn plaintext(&self, msg_id: i64) -> Option<String> {
        self.conn
            .query_row(
                "SELECT plaintext FROM messages WHERE id = ?1",
                params![msg_id],
                |r| r.get::<_, Option<String>>(0),
            )
            .optional()
            .ok()
            .flatten()
            .flatten()
    }

    // -- world cache ---------------------------------------------------------------

    pub fn upsert_friends(&self, friends: &[AccountBrief]) -> Result<(), String> {
        for f in friends {
            self.conn
                .execute(
                    "INSERT INTO friends(id, username, identity_key) VALUES(?1,?2,?3)
                     ON CONFLICT(id) DO UPDATE SET username = excluded.username,
                         identity_key = excluded.identity_key",
                    params![f.id, f.username, f.identity_key],
                )
                .map_err(|e| format!("friends: {e}"))?;
        }
        Ok(())
    }

    pub fn friends(&self) -> Vec<AccountBrief> {
        let Ok(mut stmt) = self
            .conn
            .prepare("SELECT id, username, identity_key FROM friends ORDER BY username")
        else {
            return Vec::new();
        };
        let Ok(rows) = stmt.query_map([], |r| {
            Ok(AccountBrief {
                id: r.get(0)?,
                username: r.get(1)?,
                identity_key: r.get(2)?,
                online: false,
            })
        }) else {
            return Vec::new();
        };
        rows.filter_map(|r| r.ok()).collect()
    }

    pub fn upsert_guilds(&self, guilds: &[GuildInfo]) -> Result<(), String> {
        for g in guilds {
            self.conn
                .execute(
                    "INSERT INTO guilds(id, name, owner_id) VALUES(?1,?2,?3)
                     ON CONFLICT(id) DO UPDATE SET name = excluded.name,
                         owner_id = excluded.owner_id",
                    params![g.id, g.name, g.owner_id],
                )
                .map_err(|e| format!("guilds: {e}"))?;
            for c in &g.channels {
                self.conn
                    .execute(
                        "INSERT INTO channels(id, guild_id, kind, name) VALUES(?1,?2,?3,?4)
                         ON CONFLICT(id) DO UPDATE SET guild_id = excluded.guild_id,
                             kind = excluded.kind, name = excluded.name",
                        params![c.id, g.id, kind_str_channel(&c.kind), c.name],
                    )
                    .map_err(|e| format!("channels: {e}"))?;
            }
        }
        Ok(())
    }

    pub fn guilds(&self) -> Vec<GuildInfo> {
        let mut out: Vec<GuildInfo> = Vec::new();
        let Ok(mut stmt) = self
            .conn
            .prepare("SELECT id, name, owner_id FROM guilds ORDER BY name")
        else {
            return out;
        };
        let Ok(rows) = stmt.query_map([], |r| {
            Ok(GuildInfo {
                id: r.get(0)?,
                name: r.get(1)?,
                owner_id: r.get(2)?,
                channels: Vec::new(),
            })
        }) else {
            return out;
        };
        for g in rows.filter_map(|r| r.ok()) {
            out.push(g);
        }
        if let Ok(mut stmt) = self
            .conn
            .prepare("SELECT id, guild_id, kind, name FROM channels ORDER BY name")
        {
            if let Ok(rows) = stmt.query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                ))
            }) {
                for (id, guild_id, kind, name) in rows.filter_map(|r| r.ok()) {
                    if let Some(g) = out.iter_mut().find(|g| g.id == guild_id) {
                        g.channels.push(ChannelInfo {
                            id,
                            guild_id: Some(guild_id),
                            kind: parse_kind_channel(&kind),
                            name,
                        });
                    }
                }
            }
        }
        out
    }

    pub fn upsert_dm(&self, dm: &DmChannel) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT INTO dm(channel_id, peer_id) VALUES(?1,?2)
                 ON CONFLICT(channel_id) DO UPDATE SET peer_id = excluded.peer_id",
                params![dm.channel.id, dm.peer.id],
            )
            .map_err(|e| format!("dm: {e}"))?;
        Ok(())
    }

    // (DM rows are a cache only; the authoritative list comes from Ready.)
}

// ---------------------------------------------------------------------------
// Keychain (session token)
// ---------------------------------------------------------------------------

const KEYCHAIN_SERVICE: &str = "bysyc";

/// Store the session token for `username` in the OS keychain.
pub fn keyring_set(username: &str, token: &str) -> Result<(), String> {
    keyring::Entry::new(KEYCHAIN_SERVICE, username)
        .map_err(|e| format!("keychain: {e}"))?
        .set_password(token)
        .map_err(|e| format!("keychain: {e}"))
}

/// Read the stored session token, if any.
pub fn keyring_get(username: &str) -> Option<String> {
    let entry = keyring::Entry::new(KEYCHAIN_SERVICE, username).ok()?;
    entry.get_password().ok()
}

/// Delete the stored session token (best-effort). keyring 4 renamed this
/// from `delete_password` to `delete_credential`.
pub fn keyring_delete(username: &str) {
    if let Ok(entry) = keyring::Entry::new(KEYCHAIN_SERVICE, username) {
        let _ = entry.delete_credential();
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn kind_str(k: &MessageKind) -> &'static str {
    match k {
        MessageKind::Chat => "chat",
        MessageKind::Control => "control",
    }
}

fn parse_kind(s: &str) -> MessageKind {
    match s {
        "control" => MessageKind::Control,
        _ => MessageKind::Chat,
    }
}

fn kind_str_channel(k: &bysyc_common::protocol::ChannelKind) -> &'static str {
    match k {
        bysyc_common::protocol::ChannelKind::Text => "text",
        bysyc_common::protocol::ChannelKind::Voice => "voice",
        bysyc_common::protocol::ChannelKind::Dm => "dm",
    }
}

fn parse_kind_channel(s: &str) -> bysyc_common::protocol::ChannelKind {
    match s {
        "voice" => bysyc_common::protocol::ChannelKind::Voice,
        "dm" => bysyc_common::protocol::ChannelKind::Dm,
        _ => bysyc_common::protocol::ChannelKind::Text,
    }
}

/// Convenience for locking the shared store without propagating poisoning.
pub fn lock_store(store: &std::sync::Mutex<Store>) -> std::sync::MutexGuard<'_, Store> {
    guard(store)
}
