# syntax=docker/dockerfile:1

FROM rust:1-bookworm AS builder

WORKDIR /app

# Pre-build dependencies for better layer caching.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src \
    && printf 'fn main() {}\n' > src/main.rs \
    && touch src/lib.rs \
    && cargo build --release --locked \
    && rm -rf src target/release/nogml* target/release/deps/nogml* target/release/deps/libnogml* target/release/.fingerprint/nogml*

COPY src ./src
RUN touch src/lib.rs src/main.rs \
    && cargo build --release --locked \
    && strip /app/target/release/nogml

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system nogml \
    && useradd --system --gid nogml --home-dir /var/lib/nogml --shell /usr/sbin/nologin nogml \
    && mkdir -p /var/lib/nogml \
    && chown -R nogml:nogml /var/lib/nogml

COPY --from=builder /app/target/release/nogml /usr/local/bin/nogml

LABEL org.opencontainers.image.source="https://github.com/jpoehnelt/nogml" \
      org.opencontainers.image.description="AI-first headless Rust email server with MCP, AI REST /v1, Gmail REST API v1, and IMAP4rev1" \
      org.opencontainers.image.licenses="Apache-2.0"

WORKDIR /var/lib/nogml
USER nogml

VOLUME ["/var/lib/nogml"]

EXPOSE 8080 1143

ENTRYPOINT ["nogml"]
CMD ["serve", "--bind", "0.0.0.0:8080"]
