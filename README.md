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
