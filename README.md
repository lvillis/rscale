<p align="center">
  <img src="assets/rscale-logo.svg" alt="rscale" width="420" />
</p>

<p align="center">
  <a href="https://crates.io/crates/rscale">
    <img src="https://img.shields.io/crates/v/rscale.svg" alt="crates.io version" />
  </a>
  <a href="https://docs.rs/rscale">
    <img src="https://img.shields.io/docsrs/rscale" alt="docs.rs" />
  </a>
  <a href="https://github.com/lvillis/rscale/blob/main/LICENSE">
    <img src="https://img.shields.io/crates/l/rscale.svg" alt="license" />
  </a>
  <a href="https://github.com/lvillis/rscale/releases">
    <img src="https://img.shields.io/github/v/release/lvillis/rscale" alt="GitHub release" />
  </a>
  <a href="https://github.com/lvillis/rscale/actions/workflows/e2e.yml">
    <img src="https://img.shields.io/github/actions/workflow/status/lvillis/rscale/e2e.yml?label=e2e" alt="e2e workflow status" />
  </a>
</p>

# rscale

`rscale` is a self-hosted control plane written in Rust for operating a single tailnet with Tailscale clients.

It is positioned as a Rust alternative to `headscale`, with PostgreSQL-backed state, embedded DERP/STUN support, a management API, and a static admin console.

## Capabilities

- TS2021 control-plane compatibility
- Node registration, map streaming, and session handling
- Auth key management
- ACL / grants / SSH policy distribution
- Route advertisement and approval
- DNS and DERP map distribution
- Embedded DERP relay, websocket DERP, mesh, and STUN
- PostgreSQL persistence, migrations, backup, and restore
- Static-export admin console hosted by the backend
