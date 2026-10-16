//! Local persistence: SQLite (rusqlite, bundled) for the world cache and
//! message history, plus a 0600 `secrets.json` in the same data dir for the
//! session token and pickle passphrase (deliberately not the OS keychain —
//! no keychain access prompts; the file keeps the passphrase outside the
//! SQLite store it encrypts, per ADR 0001).
//!
//! All methods take `&self`; the whole [`Store`] is shared as
//! `Arc<Mutex<Store>>` and locked briefly from the UI and network threads.
//! Message rows carry a `plaintext` column that stays `NULL` until C2/C3
//! decrypt and fill it via [`Store::set_plaintext`].

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use bysyc_common::protocol::{
    AccountBrief, AttachmentMeta, ChannelInfo, DmChannel, GuildInfo, MessageDto, MessageKind,
};
use rusqlite::{Connection, OptionalExtension, params};

use crate::crypto::Engine;
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
    plaintext      TEXT NULL,
    deleted        INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_messages_channel ON messages(channel_id);
CREATE TABLE IF NOT EXISTS file_envelopes(
    message_id INTEGER PRIMARY KEY,
    envelope   TEXT NOT NULL
);
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
        // WAL lets UI-thread reads run off the write lock, and NORMAL sync
        // under WAL trades a crash's very last commits for far faster
        // writes — fine for a cache (secrets live in their own file).
        // Best-effort: a filesystem that cannot do WAL still works as before.
        let _ = conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;");
        conn.execute_batch(SCHEMA)
            .map_err(|e| format!("migrate {}: {e}", path.display()))?;
        // `CREATE TABLE IF NOT EXISTS` does not extend an existing table with
        // new columns; add them best-effort (an error means "already there").
        let _ = conn.execute(
            "ALTER TABLE messages ADD COLUMN deleted INTEGER NOT NULL DEFAULT 0",
            [],
        );
        Ok(Store { conn })
    }

    // -- settings ----------------------------------------------------------

    pub fn setting(&self, key: &str) -> Option<String> {
        self.conn
            .prepare_cached("SELECT value FROM settings WHERE key = ?1")
            .and_then(|mut stmt| stmt.query_row(params![key], |r| r.get(0)))
            .optional()
            .ok()
            .flatten()
    }

    pub fn set_setting(&self, key: &str, value: &str) -> Result<(), String> {
        self.conn
            .prepare_cached(
                "INSERT INTO settings(key, value) VALUES(?1, ?2)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            )
            .and_then(|mut stmt| stmt.execute(params![key, value]))
            .map_err(|e| format!("settings: {e}"))?;
        Ok(())
    }

    pub fn del_setting(&self, key: &str) -> Result<(), String> {
        self.conn
            .prepare_cached("DELETE FROM settings WHERE key = ?1")
            .and_then(|mut stmt| stmt.execute(params![key]))
            .map_err(|e| format!("settings: {e}"))?;
        Ok(())
    }

    // -- audio device preferences -----------------------------------------

    /// Persisted chosen microphone device name (None = system default).
    pub fn audio_input(&self) -> Option<String> {
        self.setting("audio_input")
    }

    /// Persisted chosen speaker/output device name (None = system default).
    pub fn audio_output(&self) -> Option<String> {
        self.setting("audio_output")
    }

    /// `None` clears the stored preference (revert to default).
    pub fn set_audio_input(&self, name: Option<&str>) -> Result<(), String> {
        match name {
            Some(v) => self.set_setting("audio_input", v),
            None => self.del_setting("audio_input"),
        }
    }

    pub fn set_audio_output(&self, name: Option<&str>) -> Result<(), String> {
        match name {
            Some(v) => self.set_setting("audio_output", v),
            None => self.del_setting("audio_output"),
        }
    }

    // -- pickles (C2: generic encrypted-key-pickle store) --------------------

    /// Load the pickled blob stored under `scope` (e.g. an account-scoped
    /// pickle name C2 chooses).
    pub fn pickle(&self, scope: &str) -> Option<Vec<u8>> {
        self.conn
            .prepare_cached("SELECT pickle FROM keys WHERE scope = ?1")
            .and_then(|mut stmt| stmt.query_row(params![scope], |r| r.get(0)))
            .optional()
            .ok()
            .flatten()
    }

    pub fn put_pickle(&self, scope: &str, pickle: &[u8]) -> Result<(), String> {
        self.conn
            .prepare_cached(
                "INSERT INTO keys(scope, pickle) VALUES(?1, ?2)
                 ON CONFLICT(scope) DO UPDATE SET pickle = excluded.pickle",
            )
            .and_then(|mut stmt| stmt.execute(params![scope, pickle]))
            .map_err(|e| format!("keys: {e}"))?;
        Ok(())
    }

    /// Persist several pickles in one transaction — the crypto engine's
    /// multi-table persist pays one WAL fsync instead of one per scope.
    pub fn put_pickle_batch(&self, puts: &[(&str, &[u8])]) -> Result<(), String> {
        let run = || -> rusqlite::Result<()> {
            let tx = self.conn.unchecked_transaction()?;
            {
                let mut stmt = self.conn.prepare_cached(
                    "INSERT INTO keys(scope, pickle) VALUES(?1, ?2)
                     ON CONFLICT(scope) DO UPDATE SET pickle = excluded.pickle",
                )?;
                for (scope, pickle) in puts {
                    stmt.execute(params![scope, pickle])?;
                }
            }
            tx.commit()
        };
        run().map_err(|e| format!("keys: {e}"))
    }

    pub fn del_pickle(&self, scope: &str) -> Result<(), String> {
        self.conn
            .prepare_cached("DELETE FROM keys WHERE scope = ?1")
            .and_then(|mut stmt| stmt.execute(params![scope]))
            .map_err(|e| format!("keys: {e}"))?;
        Ok(())
    }

    /// Drop every pickled crypto blob. Called when a different account signs
    /// in on this device: the pickles belong to exactly one account (the
    /// pickle passphrase is per-username in the secrets file), so keeping them
    /// would make [`Engine::new`] fail with a wrong-passphrase error.
    pub fn clear_pickles(&self) -> Result<(), String> {
        self.conn
            .execute("DELETE FROM keys", [])
            .map_err(|e| format!("keys: {e}"))?;
        Ok(())
    }

    // -- messages --------------------------------------------------------------

    /// Row insert shared by [`Store::append_message`] and every row of
    /// [`Store::insert_message_page`] (bound once via `prepare_cached`).
    const INSERT_MESSAGE: &str = "INSERT OR IGNORE INTO messages(
                    id, channel_id, sender_id, kind, content, reply_to,
                    attachment_json, created_at_ms, plaintext)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,NULL)";

    /// Persist a server-confirmed message (optimistic temps are never
    /// persisted). Re-inserting the same id is a no-op.
    pub fn append_message(&self, m: &MessageDto) -> Result<(), String> {
        self.insert_message_page(std::slice::from_ref(m))
            .map(|_| ())
            .map_err(|e| format!("messages: {e}"))
    }

    /// Insert a batch of messages in one transaction (a WS drain burst, a
    /// REST history page): per-message autocommit would pay a WAL fsync per
    /// row. Re-inserting an existing id is a no-op, like
    /// [`Store::append_message`].
    pub fn insert_message_page(&self, dtos: &[MessageDto]) -> rusqlite::Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        {
            let mut stmt = self.conn.prepare_cached(Self::INSERT_MESSAGE)?;
            for m in dtos {
                let attachment_json = match &m.attachment {
                    Some(a) => Some(serde_json::to_string(a).unwrap_or_default()),
                    None => None,
                };
                stmt.execute(params![
                    m.id,
                    m.channel_id,
                    m.sender_id,
                    kind_str(&m.kind),
                    m.content,
                    m.reply_to,
                    attachment_json,
                    m.created_at_ms,
                ])?;
            }
        }
        tx.commit()
    }

    /// One page of cached history, newest last. `before` pages older than
    /// the given message id (mirrors the REST paging).
    pub fn messages_for(
        &self,
        channel_id: i64,
        before: Option<i64>,
        limit: u32,
    ) -> Vec<MessageDto> {
        let mut stmt = match self.conn.prepare_cached(
            "SELECT id, channel_id, sender_id, kind, content, reply_to,
                    attachment_json, created_at_ms
             FROM messages
             WHERE channel_id = ?1 AND deleted = 0 AND (?2 IS NULL OR id < ?2)
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
            .prepare_cached("UPDATE messages SET plaintext = ?2 WHERE id = ?1")
            .and_then(|mut stmt| stmt.execute(params![msg_id, text]))
            .map_err(|e| format!("messages: {e}"))?;
        Ok(())
    }

    /// The decrypted plaintext of a message, if any (C3 renders from this).
    pub fn plaintext(&self, msg_id: i64) -> Option<String> {
        self.conn
            .prepare_cached("SELECT plaintext FROM messages WHERE id = ?1")
            .and_then(|mut stmt| {
                stmt.query_row(params![msg_id], |r| r.get::<_, Option<String>>(0))
            })
            .optional()
            .ok()
            .flatten()
            .flatten()
    }

    /// Mark a message deleted (an [`crate::crypto::Envelope::Delete`] asked
    /// peers to hide it). Queries filter deleted rows out; the ciphertext
    /// stays for audit.
    pub fn delete_message(&self, msg_id: i64) -> Result<(), String> {
        self.conn
            .prepare_cached("UPDATE messages SET deleted = 1 WHERE id = ?1")
            .and_then(|mut stmt| stmt.execute(params![msg_id]))
            .map_err(|e| format!("messages: {e}"))?;
        Ok(())
    }

    /// `(id, sender_id, content)` of cached messages in a channel that still
    /// have no decrypted plaintext — the retry set for history backfill once
    /// a Megolm session share arrives.
    pub fn undecrypted(&self, channel_id: i64) -> Vec<(i64, i64, String)> {
        let Ok(mut stmt) = self.conn.prepare_cached(
            "SELECT id, sender_id, content FROM messages
             WHERE channel_id = ?1 AND deleted = 0 AND plaintext IS NULL
             ORDER BY id",
        ) else {
            return Vec::new();
        };
        let Ok(rows) = stmt.query_map(params![channel_id], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        }) else {
            return Vec::new();
        };
        rows.filter_map(|r| r.ok()).collect()
    }

    // -- file envelopes (C4 persistence) ---------------------------------------

    /// Persist the JSON of a decrypted [`crate::crypto::Envelope::File`]
    /// next to its message row. The attachment's key/nonce exist only
    /// inside that envelope, and it is written at send/decrypt time so an
    /// attachment row survives a restart without re-decrypting — the
    /// sender's own rows cannot be re-decrypted at all (the engine holds
    /// no Megolm self-import).
    pub fn set_file_envelope(&self, msg_id: i64, envelope: &str) -> Result<(), String> {
        self.conn
            .prepare_cached(
                "INSERT INTO file_envelopes(message_id, envelope) VALUES(?1, ?2)
                 ON CONFLICT(message_id) DO UPDATE SET envelope = excluded.envelope",
            )
            .and_then(|mut stmt| stmt.execute(params![msg_id, envelope]))
            .map_err(|e| format!("file_envelopes: {e}"))?;
        Ok(())
    }

    /// `(message_id, envelope JSON)` of every visible (not deleted) message
    /// in a channel that has a persisted File envelope — the rebuild set
    /// for [`crate::state::MainState::file_meta`] after a restart.
    pub fn file_envelopes(&self, channel_id: i64) -> Vec<(i64, String)> {
        let Ok(mut stmt) = self.conn.prepare_cached(
            "SELECT fe.message_id, fe.envelope FROM file_envelopes fe
             JOIN messages m ON m.id = fe.message_id
             WHERE m.channel_id = ?1 AND m.deleted = 0",
        ) else {
            return Vec::new();
        };
        let Ok(rows) = stmt.query_map(params![channel_id], |r| Ok((r.get(0)?, r.get(1)?))) else {
            return Vec::new();
        };
        rows.filter_map(|r| r.ok()).collect()
    }

    // -- outbound megolm channels (C3 bookkeeping) -----------------------------

    /// Channels for which this device holds an outbound Megolm session (i.e.
    /// we have sent there), persisted so guild-newcomer sharing survives a
    /// restart.
    pub fn save_outbound_channels(&self, channels: &HashSet<i64>) -> Result<(), String> {
        let ids: Vec<i64> = channels.iter().copied().collect();
        self.set_setting(
            "outbound_channels",
            &serde_json::to_string(&ids).unwrap_or_else(|_| "[]".into()),
        )
    }

    pub fn load_outbound_channels(&self) -> HashSet<i64> {
        self.setting("outbound_channels")
            .and_then(|s| serde_json::from_str::<Vec<i64>>(&s).ok())
            .map(|ids| ids.into_iter().collect())
            .unwrap_or_default()
    }

    // -- world cache ---------------------------------------------------------------

    pub fn upsert_friends(&self, friends: &[AccountBrief]) -> Result<(), String> {
        // One transaction for the whole list: per-row autocommit would pay
        // a WAL fsync per friend. `unchecked_transaction` is the `&self`
        // form (the Store is shared behind a Mutex, never `&mut`).
        let tx = self
            .conn
            .unchecked_transaction()
            .map_err(|e| format!("friends: {e}"))?;
        {
            let mut stmt = self
                .conn
                .prepare_cached(
                    "INSERT INTO friends(id, username, identity_key) VALUES(?1,?2,?3)
                     ON CONFLICT(id) DO UPDATE SET username = excluded.username,
                         identity_key = excluded.identity_key",
                )
                .map_err(|e| format!("friends: {e}"))?;
            for f in friends {
                stmt.execute(params![f.id, f.username, f.identity_key])
                    .map_err(|e| format!("friends: {e}"))?;
            }
        }
        tx.commit().map_err(|e| format!("friends: {e}"))
    }

    pub fn friends(&self) -> Vec<AccountBrief> {
        let Ok(mut stmt) = self
            .conn
            .prepare_cached("SELECT id, username, identity_key FROM friends ORDER BY username")
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
        // One transaction across every guild and channel row (see
        // [`Store::upsert_friends`]).
        let tx = self
            .conn
            .unchecked_transaction()
            .map_err(|e| format!("guilds: {e}"))?;
        {
            let mut guild_stmt = self
                .conn
                .prepare_cached(
                    "INSERT INTO guilds(id, name, owner_id) VALUES(?1,?2,?3)
                     ON CONFLICT(id) DO UPDATE SET name = excluded.name,
                         owner_id = excluded.owner_id",
                )
                .map_err(|e| format!("guilds: {e}"))?;
            let mut channel_stmt = self
                .conn
                .prepare_cached(
                    "INSERT INTO channels(id, guild_id, kind, name) VALUES(?1,?2,?3,?4)
                     ON CONFLICT(id) DO UPDATE SET guild_id = excluded.guild_id,
                         kind = excluded.kind, name = excluded.name",
                )
                .map_err(|e| format!("channels: {e}"))?;
            for g in guilds {
                guild_stmt
                    .execute(params![g.id, g.name, g.owner_id])
                    .map_err(|e| format!("guilds: {e}"))?;
                for c in &g.channels {
                    channel_stmt
                        .execute(params![c.id, g.id, kind_str_channel(&c.kind), c.name])
                        .map_err(|e| format!("channels: {e}"))?;
                }
            }
        }
        tx.commit().map_err(|e| format!("guilds: {e}"))
    }

    pub fn guilds(&self) -> Vec<GuildInfo> {
        let mut out: Vec<GuildInfo> = Vec::new();
        let Ok(mut stmt) = self
            .conn
            .prepare_cached("SELECT id, name, owner_id FROM guilds ORDER BY name")
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
            .prepare_cached("SELECT id, guild_id, kind, name FROM channels ORDER BY name")
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
            .prepare_cached(
                "INSERT INTO dm(channel_id, peer_id) VALUES(?1,?2)
                 ON CONFLICT(channel_id) DO UPDATE SET peer_id = excluded.peer_id",
            )
            .and_then(|mut stmt| stmt.execute(params![dm.channel.id, dm.peer.id]))
            .map_err(|e| format!("dm: {e}"))?;
        Ok(())
    }

    // (DM rows are a cache only; the authoritative list comes from Ready.)
}

// ---------------------------------------------------------------------------
// Local secrets file (session token + pickle passphrase)
// ---------------------------------------------------------------------------

/// Session tokens live under this service key in the secrets file.
const TOKEN_SERVICE: &str = "bysyc-session";
/// Separate service for the pickle passphrase (ADR 0001: the passphrase
/// never lives in the SQLite file it protects).
const PICKLE_SERVICE: &str = "bysyc-pickle";

/// `data_dir/secrets.json` — one JSON map of `"service/username"` → secret,
/// written with mode 0600 on unix. Anything unreadable counts as empty (the
/// token just falls back to the login view and the passphrase regenerates).
fn secrets_path() -> Result<PathBuf, String> {
    directories::ProjectDirs::from("", "", "bysyc")
        .map(|d| d.data_dir().join("secrets.json"))
        .ok_or_else(|| "cannot determine the platform data directory".to_string())
}

fn secrets_load() -> BTreeMap<String, String> {
    let Ok(path) = secrets_path() else {
        return BTreeMap::new();
    };
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn secrets_store(map: &BTreeMap<String, String>) -> Result<(), String> {
    let path = secrets_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("secrets: {e}"))?;
    }
    let json = serde_json::to_string_pretty(map).map_err(|e| format!("secrets: {e}"))?;
    std::fs::write(&path, json).map_err(|e| format!("secrets: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

fn secret_get(service: &str, account: &str) -> Option<String> {
    secrets_load().get(&format!("{service}/{account}")).cloned()
}

fn secret_set(service: &str, account: &str, secret: &str) -> Result<(), String> {
    let mut map = secrets_load();
    map.insert(format!("{service}/{account}"), secret.to_string());
    secrets_store(&map)
}

fn secret_remove(service: &str, account: &str) {
    let mut map = secrets_load();
    if map.remove(&format!("{service}/{account}")).is_some() {
        let _ = secrets_store(&map);
    }
}

/// Store the session token for `username` in the local secrets file.
pub fn token_set(username: &str, token: &str) -> Result<(), String> {
    secret_set(TOKEN_SERVICE, username, token)
}

/// Read the stored session token, if any.
pub fn token_get(username: &str) -> Option<String> {
    secret_get(TOKEN_SERVICE, username)
}

/// Delete the stored session token (best-effort).
pub fn token_delete(username: &str) {
    secret_remove(TOKEN_SERVICE, username);
}

/// Remove every secrets-file entry for `username` (token + pickle
/// passphrase). The e2e harness uses this to clean up its throwaway
/// accounts; the login flow uses [`token_delete`] instead (the passphrase
/// must survive logout — it still protects the pickled identity).
pub fn secret_delete_profile(username: &str) {
    secret_remove(TOKEN_SERVICE, username);
    secret_remove(PICKLE_SERVICE, username);
}

// ---------------------------------------------------------------------------
// Crypto engine bootstrap (C3)
// ---------------------------------------------------------------------------

/// Adapter that lets the engine (which holds `Arc<dyn KeyStore>`) pickle into
/// the shared [`Store`]. Failures are logged and swallowed: the engine's
/// contract wants `put` to be fire-and-forget, and a failed pickle write only
/// costs a re-share after restart, never correctness of an in-flight message.
pub struct KeyStoreImpl(pub Arc<Mutex<Store>>);

impl crate::crypto::KeyStore for KeyStoreImpl {
    fn get(&self, scope: &str) -> Option<Vec<u8>> {
        lock_store(&self.0).pickle(scope)
    }

    fn put(&self, scope: &str, blob: &[u8]) {
        if let Err(e) = lock_store(&self.0).put_pickle(scope, blob) {
            eprintln!("[bysyc] pickle write failed ({scope}): {e}");
        }
    }

    fn put_batch(&self, puts: &[(&str, &[u8])]) {
        if let Err(e) = lock_store(&self.0).put_pickle_batch(puts) {
            eprintln!("[bysyc] pickle batch write failed: {e}");
        }
    }

    fn delete(&self, scope: &str) {
        if let Err(e) = lock_store(&self.0).del_pickle(scope) {
            eprintln!("[bysyc] pickle delete failed ({scope}): {e}");
        }
    }
}

/// 32 random bytes as 64 hex chars (OS entropy via `rand`).
fn random_hex32() -> String {
    use rand::Rng;
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The passphrase protecting this account's pickles: looked up in the local
/// secrets file under `PICKLE_SERVICE`/`username`, generated and stored on
/// first login. Losing it means losing the identity (ADR 0001 accepts that:
/// one device per account, no key export in v1), so a failed *write* is an
/// error rather than a silent disposable secret.
pub fn pickle_passphrase(username: &str) -> Result<String, String> {
    if let Some(p) = secret_get(PICKLE_SERVICE, username) {
        return Ok(p);
    }
    let p = random_hex32();
    secret_set(PICKLE_SERVICE, username, &p)?;
    Ok(p)
}

/// Build the crypto engine for `username` and load the persisted outbound
/// Megolm channel set (used for share-to-newcomer bookkeeping).
///
/// Callers that may be switching accounts (login screen) should call
/// [`Store::clear_pickles`] first when the username differs from the one the
/// local state belongs to; the session-restore path calls this with the same
/// username every time.
pub fn bootstrap_engine(
    store: &Arc<Mutex<Store>>,
    username: &str,
) -> Result<(Arc<Engine>, HashSet<i64>), String> {
    let passphrase = pickle_passphrase(username)?;
    let engine = Engine::new(Arc::new(KeyStoreImpl(store.clone())), passphrase)
        .map_err(|e| format!("crypto engine init failed: {e}"))?;
    let outbound = lock_store(store).load_outbound_channels();
    Ok((Arc::new(engine), outbound))
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh Store in a unique temp file (tests never touch the real DB).
    fn tmp_store(tag: &str) -> Store {
        let path = std::env::temp_dir().join(format!(
            "bysyc-test-{}-{tag}-{}.db",
            std::process::id(),
            now_tag()
        ));
        Store::open(&path).expect("open temp store")
    }

    fn now_tag() -> u64 {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        N.fetch_add(1, Ordering::Relaxed)
    }

    fn msg(id: i64, channel: i64) -> MessageDto {
        MessageDto {
            id,
            channel_id: channel,
            sender_id: 7,
            kind: MessageKind::Chat,
            content: format!("cipher-{id}"),
            reply_to: None,
            attachment: None,
            created_at_ms: id * 1000,
        }
    }

    #[test]
    fn outbound_channels_roundtrip() {
        let s = tmp_store("outbound");
        assert!(s.load_outbound_channels().is_empty());
        let mut set = HashSet::new();
        set.insert(1);
        set.insert(42);
        s.save_outbound_channels(&set).unwrap();
        assert_eq!(s.load_outbound_channels(), set);
        // Reopen semantics: settings persist in the same file; overwrite wins.
        let set2 = HashSet::from([42]);
        s.save_outbound_channels(&set2).unwrap();
        assert_eq!(s.load_outbound_channels(), set2);
    }

    #[test]
    fn undecrypted_tracks_plaintext_and_delete() {
        let s = tmp_store("undecrypted");
        s.append_message(&msg(1, 10)).unwrap();
        s.append_message(&msg(2, 10)).unwrap();
        s.append_message(&msg(3, 10)).unwrap();

        let rows = s.undecrypted(10);
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0], (1, 7, "cipher-1".to_string()));

        // Decrypting one row removes just it from the retry set.
        s.set_plaintext(2, "hello").unwrap();
        assert_eq!(s.undecrypted(10).len(), 2);
        assert_eq!(s.plaintext(2).as_deref(), Some("hello"));

        // A Delete hides the row from history and from the retry set.
        s.delete_message(3).unwrap();
        let visible: Vec<i64> = s.messages_for(10, None, 50).iter().map(|m| m.id).collect();
        assert_eq!(visible, vec![1, 2]);
        assert_eq!(s.undecrypted(10).len(), 1);

        // Plaintext of a deleted row is irrelevant (never rendered).
        s.delete_message(2).unwrap();
        let visible: Vec<i64> = s.messages_for(10, None, 50).iter().map(|m| m.id).collect();
        assert_eq!(visible, vec![1]);
    }

    #[test]
    fn insert_message_page_batches_are_idempotent() {
        let s = tmp_store("page");
        let batch: Vec<MessageDto> = (1..=5).map(|i| msg(i, 10)).collect();
        s.insert_message_page(&batch).unwrap();
        // Re-inserting (a WS replay, a refetched history page) is a no-op.
        s.insert_message_page(&batch).unwrap();
        s.append_message(&msg(2, 10)).unwrap();
        let ids: Vec<i64> = s.messages_for(10, None, 50).iter().map(|m| m.id).collect();
        assert_eq!(ids, vec![1, 2, 3, 4, 5]);
        // The single-message path and the batch path write the same rows.
        s.insert_message_page(&[msg(6, 10)]).unwrap();
        assert_eq!(s.messages_for(10, None, 50).len(), 6);
    }

    #[test]
    fn clear_pickles_wipes_every_scope() {
        let s = tmp_store("pickles");
        s.put_pickle("olm_account", b"blob-a").unwrap();
        s.put_pickle("megolm_out", b"blob-b").unwrap();
        assert_eq!(
            s.pickle("olm_account").as_deref(),
            Some(b"blob-a".as_slice())
        );
        s.clear_pickles().unwrap();
        assert!(s.pickle("olm_account").is_none());
        assert!(s.pickle("megolm_out").is_none());
    }

    #[test]
    fn file_envelopes_roundtrip_per_channel_and_skip_deleted() {
        let s = tmp_store("file-env");
        s.append_message(&msg(1, 10)).unwrap();
        s.append_message(&msg(2, 20)).unwrap();
        s.set_file_envelope(1, r#"{"file":{"name":"a"}}"#).unwrap();
        s.set_file_envelope(2, r#"{"file":{"name":"b"}}"#).unwrap();
        // Scoped to the channel, envelope JSON verbatim.
        assert_eq!(
            s.file_envelopes(10),
            vec![(1, r#"{"file":{"name":"a"}}"#.to_string())]
        );
        assert_eq!(
            s.file_envelopes(20),
            vec![(2, r#"{"file":{"name":"b"}}"#.to_string())]
        );
        // One row per message: a re-write replaces, never duplicates.
        s.set_file_envelope(1, r#"{"file":{"name":"a2"}}"#).unwrap();
        assert_eq!(s.file_envelopes(10).len(), 1);
        // A deleted message's envelope is not rebuilt after a restart.
        s.delete_message(1).unwrap();
        assert!(s.file_envelopes(10).is_empty());
    }

    #[test]
    fn random_hex32_shape() {
        let h = random_hex32();
        assert_eq!(h.len(), 64);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(h, random_hex32());
    }
}
