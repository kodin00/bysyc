//! Shared integration-test harness for the server crate.
//!
//! One set of ephemeral backing services (Postgres, Redis, LocalStack S3) is
//! started via testcontainers ONCE per test binary, on a dedicated tokio
//! runtime that outlives every `#[tokio::test]` (which dies with its test).
//! The WS event bus is installed on that same long-lived runtime so its
//! Redis subscriber workers survive individual test runtimes.
//!
//! Each test then boots its own server against the shared containers: its own
//! AppState, its own `127.0.0.1:0` port, its own per-IP auth rate limiter.
//! Concurrent tests stay isolated because every account/guild/channel gets a
//! globally unique auto-increment id, so the derived Redis topics
//! (`acct:{id}`, `chan:{id}`) never collide across tests.

// Each test binary uses a different subset of these helpers (the REST-only
// binary never touches ws_url; the voice binary never calls register/login).
// Suppress the per-binary "never used" warnings that would otherwise fail
// `cargo clippy -- -D warnings` on the binaries that don't touch a given
// helper.
#![allow(dead_code)]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use bysyc_common::protocol::{
    ApiError, LoginRequest, RegisterRequest, TokenResponse,
};
use testcontainers::{
    core::{IntoContainerPort, WaitFor},
    runners::AsyncRunner,
    GenericImage, ImageExt,
};

use bysyc_server::ws;
use bysyc_server::{boot, router, session, AppState, Config};

/// How long a readiness poll keeps retrying before giving up. First runs pay
/// the image pull; warm runs finish in a second or two.
const READINESS_TIMEOUT: Duration = Duration::from_secs(120);

// ---------------------------------------------------------------------------
// Backing services (one set per test binary, on a dedicated runtime)
// ---------------------------------------------------------------------------

/// Connection URLs for the shared backing services.
struct EnvUrls {
    database_url: String,
    redis_url: String,
    s3_endpoint: String,
}

static ENV: OnceLock<EnvUrls> = OnceLock::new();

/// The running containers. Held by the parked infra thread so `Drop` (which
/// removes them) only runs at process exit — tests reuse one set.
struct Containers {
    _pg: testcontainers::ContainerAsync<GenericImage>,
    _redis: testcontainers::ContainerAsync<GenericImage>,
    _s3: testcontainers::ContainerAsync<GenericImage>,
}

/// Start (once) and return the backing-service URLs.
fn env() -> &'static EnvUrls {
    ENV.get_or_init(|| {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(2)
            .build()
            .expect("build infra runtime");
        let (tx, rx) = std::sync::mpsc::channel::<EnvUrls>();
        std::thread::Builder::new()
            .name("bysyc-test-infra".into())
            .spawn(move || {
                let (urls, containers) = rt
                    .block_on(start_backing_services())
                    .expect("start backing services");
                // Install the WS event bus on THIS runtime: its subscriber
                // workers must outlive every test, and a per-test runtime is
                // torn down with its test.
                ws::start_event_bus(&urls.redis_url, 2);
                tx.send(urls).expect("send env urls");
                // Park forever: the runtime, the containers, and the bus
                // workers stay alive until the process exits.
                rt.block_on(async move {
                    let _containers = containers;
                    std::future::pending::<()>().await;
                });
            })
            .expect("spawn infra thread");
        rx.recv().expect("backing services started")
    })
}

async fn start_backing_services(
) -> Result<(EnvUrls, Containers), Box<dyn std::error::Error + Send + Sync>> {
    let pg = GenericImage::new("postgres", "16")
        .with_exposed_port(5432.tcp())
        .with_wait_for(WaitFor::message_on_stderr(
            "database system is ready to accept connections",
        ))
        .with_env_var("POSTGRES_USER", "bysyc")
        .with_env_var("POSTGRES_PASSWORD", "bysyc")
        .with_env_var("POSTGRES_DB", "bysyc")
        .start()
        .await?;
    let redis = GenericImage::new("redis", "7")
        .with_exposed_port(6379.tcp())
        .with_wait_for(WaitFor::message_on_stdout(
            "Ready to accept connections",
        ))
        .start()
        .await?;
    let s3 = GenericImage::new("localstack/localstack", "latest")
        .with_exposed_port(4566.tcp())
        .with_env_var("SERVICES", "s3")
        .start()
        .await?;

    let pg_port = pg.get_host_port_ipv4(5432).await?;
    let redis_port = redis.get_host_port_ipv4(6379).await?;
    let s3_port = s3.get_host_port_ipv4(4566).await?;

    // The log waits above are the fast path; these probes are the
    // authoritative readiness check (and cover a log-format drift).
    let database_url = format!("postgres://bysyc:bysyc@127.0.0.1:{pg_port}/bysyc");
    let redis_url = format!("redis://127.0.0.1:{redis_port}");
    let s3_endpoint = format!("http://127.0.0.1:{s3_port}");
    wait_for_pg(&database_url).await?;
    wait_for_tcp(&format!("127.0.0.1:{redis_port}")).await?;
    wait_for_http_200(&format!("{s3_endpoint}/_localstack/health")).await?;

    Ok((
        EnvUrls {
            database_url,
            redis_url,
            s3_endpoint,
        },
        Containers {
            _pg: pg,
            _redis: redis,
            _s3: s3,
        },
    ))
}

async fn wait_for_pg(url: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let deadline = Instant::now() + READINESS_TIMEOUT;
    loop {
        if Instant::now() > deadline {
            return Err(format!("postgres never became ready at {url}").into());
        }
        if sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(url)
            .await
            .is_ok()
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

async fn wait_for_tcp(addr: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let deadline = Instant::now() + READINESS_TIMEOUT;
    loop {
        if Instant::now() > deadline {
            return Err(format!("tcp {addr} never became ready").into());
        }
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
}

async fn wait_for_http_200(url: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client = reqwest::Client::builder().build()?;
    let deadline = Instant::now() + READINESS_TIMEOUT;
    loop {
        if Instant::now() > deadline {
            return Err(format!("HTTP 200 never observed at {url}").into());
        }
        if let Ok(resp) = client.get(url).send().await
            && resp.status().is_success()
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

// ---------------------------------------------------------------------------
// Per-test harness
// ---------------------------------------------------------------------------

/// One booted server: HTTP base URL, WS URL, direct-DB AppState, and the
/// serving task (aborted on drop). Backing services are shared, the server
/// is per-test. `ws_url` is read by the WS/voice test binaries; REST-only
/// binaries leave it untouched (hence the allow).
pub struct Harness {
    pub base_url: String,
    #[allow(dead_code)]
    pub ws_url: String,
    pub state: AppState,
    server: tokio::task::JoinHandle<()>,
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.server.abort();
    }
}

/// Boot a fresh server against the shared backing services and bind it to an
/// ephemeral loopback port. Runs migrations (idempotent after the first
/// boot), registers no routes beyond the production router.
pub async fn setup() -> Harness {
    let env = env();
    let config = Config {
        database_url: env.database_url.clone(),
        redis_url: env.redis_url.clone(),
        s3_endpoint: env.s3_endpoint.clone(),
        s3_access_key: "test".into(),
        s3_secret_key: "test".into(),
        s3_bucket: "bysyc".into(),
        turn_addr: "localhost:3478".into(),
        turn_user: "bysyc".into(),
        turn_password: "bysyc".into(),
        attachment_max_bytes: 50 * 1024 * 1024,
        db_max_connections: 4,
    };
    let state = boot(&config).await.expect("boot");
    let app = router(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("local_addr").port();
    let server = tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await;
    });
    Harness {
        base_url: format!("http://127.0.0.1:{port}"),
        ws_url: format!("ws://127.0.0.1:{port}/ws"),
        state,
        server,
    }
}

// ---------------------------------------------------------------------------
// Fixtures and REST helpers
// ---------------------------------------------------------------------------

/// Unique-suffix counter: usernames and invite codes minted straight into
/// the DB only need to be unique within this process.
static NAME_COUNTER: AtomicU64 = AtomicU64::new(1);

/// A username unique across all tests in this binary (`u{tag}_{n}`).
pub fn unique_name(tag: &str) -> String {
    format!("u{}_{}", tag, NAME_COUNTER.fetch_add(1, Ordering::Relaxed))
}

/// Mint a registration invite directly in the DB. This bypasses
/// `db::bootstrap`/`db::make_invite` (both print the code to stdout instead
/// of returning it). The first account to register on a fresh database
/// becomes the Instance admin (see `auth::register`).
pub async fn mint_invite(state: &AppState) -> String {
    let code = format!("inv{}", NAME_COUNTER.fetch_add(1, Ordering::Relaxed));
    sqlx::query("INSERT INTO registration_invites(code) VALUES ($1)")
        .bind(&code)
        .execute(&state.pg)
        .await
        .unwrap_or_else(|e| panic!("mint invite: {e}"));
    code
}

/// Direct-DB-insert an admin account and mint a session token for it.
/// Avoids the "first registrant becomes admin" race when tests run
/// concurrently against the shared DB: this account is admin by row, not
/// by being first. The password hash is a dummy (`'x'`) — never log in via
/// REST; use the returned token for direct API calls.
pub async fn mint_admin(state: &AppState) -> (String, i64) {
    let username = unique_name("admin");
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO accounts(username, password_hash, identity_key, is_admin) \
         VALUES ($1, 'x', 'a2V5', true) RETURNING id",
    )
    .bind(&username)
    .fetch_one(&state.pg)
    .await
    .unwrap_or_else(|e| panic!("mint admin: {e}"));
    let token = session::create(&state.redis, id)
        .await
        .map_err(|e| format!("session create: {:?} {}", e.code, e.message))
        .unwrap();
    (token, id)
}

/// Register an account; panics unless it succeeds. Returns (token, id).
pub async fn register(base: &str, username: &str, password: &str, invite: &str) -> (String, i64) {
    let resp = reqwest::Client::new()
        .post(format!("{base}/auth/register"))
        .json(&RegisterRequest {
            username: username.to_string(),
            password: password.to_string(),
            invite_code: invite.to_string(),
            identity_key: "a2V5".to_string(),
        })
        .send()
        .await
        .unwrap_or_else(|e| panic!("register {username}: {e}"));
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        panic!("register {username}: expected success, got {status}: {body}");
    }
    let tr: TokenResponse = resp
        .json()
        .await
        .unwrap_or_else(|e| panic!("register {username}: decode response: {e}"));
    (tr.token, tr.account.id)
}

/// Register and return the outcome instead of panicking, for the
/// expected-failure cases (bad or already-used invite).
pub async fn register_status(
    base: &str,
    username: &str,
    password: &str,
    invite: &str,
) -> (reqwest::StatusCode, Option<ApiError>) {
    let resp = reqwest::Client::new()
        .post(format!("{base}/auth/register"))
        .json(&RegisterRequest {
            username: username.to_string(),
            password: password.to_string(),
            invite_code: invite.to_string(),
            identity_key: "a2V5".to_string(),
        })
        .send()
        .await
        .unwrap_or_else(|e| panic!("register {username}: {e}"));
    let status = resp.status();
    let err = if status.is_success() {
        None
    } else {
        resp.json::<ApiError>().await.ok()
    };
    (status, err)
}

/// Log in; panics unless it succeeds. Returns (token, id).
pub async fn login(base: &str, username: &str, password: &str) -> (String, i64) {
    let resp = reqwest::Client::new()
        .post(format!("{base}/auth/login"))
        .json(&LoginRequest {
            username: username.to_string(),
            password: password.to_string(),
        })
        .send()
        .await
        .unwrap_or_else(|e| panic!("login {username}: {e}"));
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        panic!("login {username}: expected success, got {status}: {body}");
    }
    let tr: TokenResponse = resp
        .json()
        .await
        .unwrap_or_else(|e| panic!("login {username}: decode response: {e}"));
    (tr.token, tr.account.id)
}
