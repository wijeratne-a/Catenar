FROM rust:1.88-bookworm AS builder

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --gid 10001 aegis \
    && useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin aegis

WORKDIR /app
COPY --from=builder /app/target/release/aegis-proxy .
RUN mkdir -p /var/lib/aegis /tmp \
    && chown -R 10001:10001 /app /var/lib/aegis /tmp

EXPOSE 8080

USER 10001:10001

ENTRYPOINT ["./aegis-proxy"]
