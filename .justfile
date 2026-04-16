set shell := ["bash", "-euo", "pipefail", "-c"]

patch:
    cargo release patch --no-publish --execute

publish:
    cargo publish --workspace

ci:
    cargo fmt --all
    cargo check --all-features --locked
    cargo clippy --all-targets --all-features --locked -- -D warnings
    cargo nextest run --all-features --locked
