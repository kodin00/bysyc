# Deploying bysyc on a VPS

Self-host one bysyc Instance on a single Linux VPS using the bundled
`docker-compose.yml`. This covers a public deployment with TLS and a working
TURN relay for voice calls across hard NATs.

## Architecture (one host)

```
Internet ──► Caddy :443 (TLS) ──► bysyc-server :8080 (HTTP + WS gateway)
                  │
                  └─ ACME :80

coturn :3478 + :49160-49200/udp  ◄── WebRTC peers (mesh voice)

[internal, loopback only — never exposed]
  postgres :15432 · redis :16379 · seaweedfs-s3 :8333
```

bysyc-server is axum over **plain HTTP** — it has no built-in TLS. On a public
VPS you must put a reverse proxy (Caddy recommended) in front of it to
terminate TLS. WebSocket upgrade passes through transparently. Postgres, Redis,
and SeaweedFS are already bound to `127.0.0.1` in compose; keep them that way.

## Ports to open

Open these on the VPS firewall / cloud security group:

| Port | Proto | Service | Why |
|------|-------|---------|-----|
| **443** | tcp | Caddy → server | Client API + WebSocket gateway (`wss://`) |
| **80** | tcp | Caddy | Let's Encrypt ACME challenge + HTTP→HTTPS redirect |
| **3478** | tcp+udp | coturn | TURN allocation / control |
| **49160–49200** | udp | coturn | TURN relay range — carries relayed voice media |

Keep **closed** (loopback/internal only):

| Port | Service | Note |
|------|---------|------|
| 8080 | bysyc-server | Bound publicly by compose — see [Lock down 8080](#lock-down-8080) |
| 15432 | postgres | Loopback in compose; never open |
| 16379 | redis | Loopback in compose; never open |
| 8333 | seaweedfs-s3 | Loopback in compose; server-only; never open |

`ufw` example:

```
ufw allow 443/tcp
ufw allow 80/tcp
ufw allow 3478/tcp
ufw allow 3478/udp
ufw allow 49160:49200/udp
ufw deny 8080/tcp
ufw enable
```

> TURN relay ports are **ephemeral allocation** ports, not fixed per user. The
> range `49160–49200` (41 ports) suits a small group; scale the range with
> expected concurrent relayed peers, and match `--min-port`/`--max-port` in the
> compose `coturn` command.

## Prerequisites

- A Linux VPS (2 vCPU / 2 GB RAM is plenty for a small friend group).
- Docker + the `docker compose` plugin.
- A DNS A/AAAA record pointing at the VPS public IP, e.g. `bysyc.example.com`.
- (Optional but recommended) `ufw` or the cloud provider's security group.

## 1. Configure secrets

```bash
git clone <your-repo> bysyc && cd bysyc
cp .env.example .env
```

Edit `.env` — every `change-me` must be set:

```dotenv
POSTGRES_PASSWORD=<strong random>
TURN_PASSWORD=<strong random>
S3_ACCESS_KEY=<strong random>
S3_SECRET_KEY=<strong random>

# Public address clients dial the TURN relay on (reachable from the internet):
TURN_ADDR=bysyc.example.com:3478
# coturn advertises this as its relay candidate address (the VPS public IP):
COTURN_EXTERNAL_IP=<VPS PUBLIC IP>
```

Put the **same** `S3_ACCESS_KEY` / `S3_SECRET_KEY` into the SeaweedFS S3
config (compose mounts it read-only):

```bash
$EDITOR deploy/seaweedfs/s3.json   # set accessKey/secretKey in the "bysyc" identity
```

## 2. Point coturn at the public IP

coturn advertises `--external-ip` to clients so relayed ICE candidates are
reachable. The compose file reads it from `COTURN_EXTERNAL_IP` (default
`127.0.0.1`, fine for local dev). Set it to the VPS public IP in `.env`:

```dotenv
COTURN_EXTERNAL_IP=<VPS PUBLIC IP>
```

If the VPS sits behind 1:1 NAT (public IP not bound to a local interface), use
the `PUBLIC/PRIVATE` form: `COTURN_EXTERNAL_IP=203.0.113.5/10.0.0.5`.

## 3. Add a TLS reverse proxy (Caddy)

Caddy auto-provisions Let's Encrypt certs for your domain and proxies both
HTTP and WebSocket to the server.

`/etc/caddy/Caddyfile`:

```caddy
bysyc.example.com {
    encode zstd gzip

    # WebSocket gateway + REST API
    reverse_proxy 127.0.0.1:8080 {
        header_up Host {host}
        header_up X-Real-IP {remote_host}
        header_up X-Forwarded-For {remote_host}
        header_up X-Forwarded-Proto {scheme}
    }
}
```

Install and enable Caddy (Debian/Ubuntu):

```bash
sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo apt update && sudo apt install caddy
sudo systemctl enable --now caddy
```

DNS must already resolve before Caddy starts, or the ACME order fails.

### <a name="lock-down-8080"></a>Lock down 8080

Compose publishes `8080:8080` on all interfaces. With Caddy in front you don't
want clients bypassing TLS. Bind it loopback-only — edit `docker-compose.yml`:

```yaml
  server:
    ports:
      - "127.0.0.1:8080:8080"
```

(If you skip Caddy entirely and serve plain HTTP on 8080, leave the bind as-is
and open `8080/tcp` instead of 443 — but **not recommended**: chat credentials
and the WS gateway would traverse the internet in cleartext.)

## 4. Bring it up

```bash
docker compose up -d --build
docker compose ps              # all services healthy/started
curl -s https://bysyc.example.com/healthz   # → ok
```

First boot against a fresh database prints a first-registration token to the
server logs — the first person to register with it becomes the Instance
admin:

```bash
docker compose logs server | grep -i "first-registration"
```

The admin can then mint further single-use invite codes from the client's
Settings → Invites panel. The operator can also mint one from the host:

```bash
set -a; . ./.env; set +a
docker compose run --rm server make-invite
```

## 5. Connect clients

Friends register from the client's login screen (Register tab, paste an
invite code). Point the client at the public URL:

```
https://bysyc.example.com
```

The client derives its WebSocket URL from this — `wss://` under TLS. Voice
calls dial the TURN relay at the `TURN_ADDR` you set (`bysyc.example.com:3478`).

## Verifying each piece

| Check | Expected |
|-------|----------|
| `curl https://<host>/healthz` | `ok` |
| `docker compose logs server` | `bysyc-server listening on 0.0.0.0:8080` + invite code on first boot |
| `docker compose logs coturn` | no `Cannot bind` errors; allocations appear when a call starts |
| Client login over `https://` | connects; gateway upgrades to `wss://` |
| Start a voice call | participants connect; relayed peers show in coturn logs |

## Hardening

Because bysyc is end-to-end encrypted, your risk as the server owner is **not**
"leaked message history" — the server holds only ciphertext and no keys. The
real risks are **abuse** (TURN bandwidth, attachment storage, WS sockets),
**availability** (DoS), and **admin-account takeover**. Spend hardening budget
on the edge first.

### Already in place

- **Argon2id** password hashing (OWASP baseline, constant-time verify,
  run off the async runtime via `spawn_blocking`).
- **Invite-gated registration** — codes are single-use; no open signups.
- **Attachment size cap** — `ATTACHMENT_MAX_MB` (default 50) enforced on both
  metadata and body.
- **In-app login rate limit** — `/auth/login` and `/auth/register` are
  per-IP rate-limited (default 5 req/min/IP via `AUTH_RATE_PER_MIN`; exceeding
  returns `429`). Tunable in `.env`. Raise it only if legitimate users get
  throttled.
- **Non-root server container** — the `bysyc-server` process runs as uid 1000,
  not root.
- Backing services loopback-bound in compose.

### Still recommended at the edge

- **Cap WS connections per IP** at the proxy. The in-app limiter guards
  login/register; a malicious client can still open many gateway sockets. Use
  `nft`/`ufw` conntrack limits on 443, or a Caddy plugin.
- **Reverse-proxy rate limit** on the WS upgrade path if you observe abuse.
- **Block :8080** publicly (see [Lock down 8080](#lock-down-8080)) so no one
  bypasses TLS to the raw HTTP server.

### Operational

- All secrets in `.env` are real — `chmod 600 .env` (the client already keeps
  its secrets in a 0600 file; do the same server-side). For real rotation,
  encrypt at rest with `sops`/`age` so a disk-image leak doesn't hand over all
  four. Back `.env` up somewhere safe; losing `POSTGRES_PASSWORD` locks you
  out of your own DB.
- **Rotate on compromise:** all 4 secrets. `POSTGRES_PASSWORD` rotation also
  needs `ALTER USER bysyc PASSWORD '...'` in the DB — changing `.env` alone
  won't update the existing role.
- The TURN credential is one static shared user (`bysyc` / `TURN_PASSWORD`).
  Anyone who learns it can burn your relay bandwidth. Rotate by changing
  `TURN_PASSWORD` and restarting coturn (clients pick up the new value via the
  API on the next call). For growth beyond a small group, switch coturn to the
  **TURN REST API** (time-limited HMAC credentials per call) instead of the
  static user.
- Keep the TURN UDP relay range tight (`49160–49200` ≈ 41 ports for a small
  group); scale it with relayed-peer count, matching `--min-port`/`--max-port`
  and the firewall rule together.
- Never expose Postgres / Redis / SeaweedFS to the public internet — they stay
  loopback-bound in compose.
- Back up the `seaweed` and `pgdata` Docker volumes if you want ciphertext
  message history to survive a host rebuild. Treat backups as sensitive
  (metadata: who messaged whom, when) even though they hold no keys.
- Patch the host (`unattended-upgrades`); pin and rebuild images on a schedule.
- Monitor coturn allocation logs for spikes (relay abuse), and watch
  `DB_MAX_CONNECTIONS` (default 16) saturation under load.
- One device per account — a second login supersedes the first (v1 limit).
