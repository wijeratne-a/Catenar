# Stage 1: Build
FROM rust:1.88-bookworm AS builder

WORKDIR /app

# Copy manifests first for better layer caching
COPY Cargo.toml Cargo.lock ./
COPY src ./src

# Build release binary
RUN cargo build --release

# Stage 2: Runtime
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --gid 10001 aegis \
    && useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin aegis

WORKDIR /app

COPY --from=builder /app/target/release/aegis-api .
RUN mkdir -p /tmp \
    && chown -R 10001:10001 /app /tmp
EXPOSE 3000

USER 10001:10001

ENTRYPOINT ["./aegis-api"]
