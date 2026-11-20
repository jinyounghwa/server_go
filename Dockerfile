# syntax=docker/dockerfile:1
FROM rust:1-slim-bookworm AS builder
WORKDIR /src
COPY core/Cargo.toml core/Cargo.lock* ./
COPY core/src ./src
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates python3 && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 10001 rocalcloud
COPY --from=builder /src/target/release/rocalcloud /usr/local/bin/rocalcloud
USER rocalcloud
ENV BIND=0.0.0.0:4566
EXPOSE 4566
# Publish on loopback only: docker run --rm -p 127.0.0.1:4566:4566 rocalcloud
ENTRYPOINT ["rocalcloud"]
