ARG RUST_VERSION=1.95.0

FROM node:22-trixie-slim AS web-builder

ARG TARGETPLATFORM

ENV PNPM_HOME=/pnpm
ENV PATH="${PNPM_HOME}:${PATH}"

RUN corepack enable

WORKDIR /work/web

COPY web/package.json web/pnpm-lock.yaml web/pnpm-workspace.yaml ./
RUN --mount=type=cache,id=pnpm-store-${TARGETPLATFORM},target=/pnpm/store,sharing=locked \
    pnpm install --frozen-lockfile

COPY web/ ./
RUN --mount=type=cache,id=pnpm-store-${TARGETPLATFORM},target=/pnpm/store,sharing=locked \
    pnpm build

FROM rust:${RUST_VERSION}-trixie AS rust-builder

ARG TARGETPLATFORM

WORKDIR /work

COPY Cargo.toml Cargo.lock ./
COPY crates/rscale ./crates/rscale

RUN --mount=type=cache,id=cargo-registry-${TARGETPLATFORM},target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=cargo-git-${TARGETPLATFORM},target=/usr/local/cargo/git/db,sharing=locked \
    --mount=type=cache,id=cargo-target-${TARGETPLATFORM},target=/work/target,sharing=locked \
    cargo build --release --package rscale


FROM debian:trixie-slim AS runtime

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --home-dir /app --shell /usr/sbin/nologin rscale

WORKDIR /app

COPY --from=rust-builder /work/target/release/rscale /usr/local/bin/rscale
COPY --from=web-builder /work/web/out /app/web/out
COPY config/config.example.toml /app/config/config.example.toml

ENV RSCALE_CONFIG=/app/config/config.toml
ENV RSCALE_WEB_ROOT=/app/web/out

RUN mkdir -p /app/config \
    && chown -R rscale:rscale /app

USER rscale:rscale

EXPOSE 8080/tcp
EXPOSE 3478/udp

ENTRYPOINT ["rscale"]
CMD ["server"]
