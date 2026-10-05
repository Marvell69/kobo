build:
    cargo build --workspace

test:
    cargo test --workspace

check:
    cargo check --workspace
    cargo clippy --workspace -- -D warnings

fmt:
    cargo fmt --all

run:
    cargo run -p kobo-server

migrate:
    # placeholder: wire sqlx-cli once crates/store grows real migrations
    echo "run sqlx migrate once DATABASE_URL is live"
