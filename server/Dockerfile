# Build context must be the workspace root (docker-compose.yml sets this).
# NOTE: plain `cargo build` busts the cache on every source change — switch to
# cargo-chef when build times start to hurt.
FROM rust:1.99 AS build
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY common ./common
COPY client ./client
COPY server ./server
RUN cargo build --release -p bysyc-server

FROM debian:bookworm-slim
COPY --from=build /build/target/release/bysyc-server /usr/local/bin/bysyc-server
EXPOSE 8080
ENTRYPOINT ["bysyc-server"]
