# Build context must be the workspace root (docker-compose.yml sets this).
# NOTE: plain `cargo build` busts the cache on every source change — switch to
# cargo-chef when build times start to hurt.
FROM rust:1.99 AS build
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY common ./common
# Only the manifest is needed for workspace resolution — the server never
# depends on the client, so copying the whole client tree would bust the
# build cache on every client-only change for no benefit.
COPY client/Cargo.toml ./client/Cargo.toml
COPY server ./server
RUN cargo build --release -p bysyc-server

# Runtime must match the builder's glibc (rust:1.99 is trixie, glibc >= 2.38;
# bookworm's 2.36 fails with "GLIBC_2.38 not found").
FROM debian:trixie-slim
# ca-certificates: any outbound TLS the server makes. tini: PID 1 that reaps
# zombies and forwards SIGTERM for clean shutdown. wget: the healthcheck
# probe (usable by the non-root bysyc user — apt installs it 0755).
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates tini wget \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /build/target/release/bysyc-server /usr/local/bin/bysyc-server
# Drop root at runtime — state lives in Postgres/Redis/S3, never the fs.
RUN useradd -r -u 1000 -M -s /usr/sbin/nologin bysyc
USER bysyc
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=15s --retries=3 \
    CMD ["wget", "-qO-", "localhost:8080/healthz"]
ENTRYPOINT ["tini", "--", "bysyc-server"]
