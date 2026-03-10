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

RUN groupadd --gid 10001 catenar \
    && useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin catenar

WORKDIR /app

COPY --from=builder /app/target/release/catenar-api .
RUN mkdir -p /tmp \
    && chown -R 10001:10001 /app /tmp
EXPOSE 3000

USER 10001:10001

ENTRYPOINT ["./catenar-api"]
