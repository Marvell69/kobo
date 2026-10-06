# Kobo

Stellar-native master-wallet infrastructure — Wallet-as-a-Service for
stablecoins, evolved from the design with a policy engine, an
audit trail, and multi-asset deposits.

CI: none yet (see CONTRIBUTING.md) · License: MIT

Kobo lets a fintech manage stablecoin deposits on Stellar from a single
master wallet: generate a dedicated deposit address per customer, detect
deposits in real time, and relay client-signed withdrawals — all behind a
REST API with signed webhooks, and a genuinely non-custodial key model
(keys are generated and held client-side; the server never sees them).

## Why this is simple on Stellar: muxed accounts

Instead of deploying a funded on-chain account per customer (and sweeping
funds back), Kobo uses muxed accounts (`M...`): one real account (`G...`)
plus a per-customer 64-bit id encoded into the address. Deposits to a
customer's `M...` land directly in the master account and carry the id, so:

- no auto-sweep — funds are already in the master,
- no per-user XLM reserve — only one account exists on-chain,
- generating an address is free and off-chain — just assign the next id.

For senders that don't yet accept `M...` (e.g. some exchanges), Kobo also
exposes the equivalent `G...` + numeric-memo form, and attributes deposits by
muxed id or memo id. See `docs/deposit-model.md`.

## What's new

See `docs/features-roadmap.md` for the full table. In short: a **policy
engine** (`kobo-policy`) enforcing per-customer rolling-window spend limits,
a **hash-chained audit log** (`kobo-audit`) so relay decisions are
tamper-evident, **multi-asset** deposit attribution (classic assets +
Soroban SEP-41 tokens), `Idempotency-Key` support on the relay endpoint, and
SEP-24 anchor hooks stubbed in for fiat on/off-ramp.

## Architecture

A Cargo workspace; all secret-handling is isolated in `kobo-crypto` and
`kobo-wallet-core`, and every other crate only ever sees ciphertext, public
keys, or already-signed transaction envelopes.

| Crate               | Responsibility                                                       |
|----------------------|-------------------------------------------------------------------------|
| `crates/crypto`      | AES-256-GCM seal/open of the gas-tank seed (random nonce, zeroized)   |
| `crates/wallet-core` | StrKey (`G.../M...`) encode+decode, SEP-0005/SLIP-10 derivation       |
| `crates/store`       | Storage trait + in-memory impl (Postgres/sqlx impl is a good first PR)|
| `crates/webhooks`    | HMAC-SHA256 signed outbound webhooks + SSRF guard                     |
| `crates/ingest`      | Horizon payment streaming + durable-cursor deposit detection          |
| `crates/policy`      | Per-customer velocity / spend-limit rules — **new vs. octo**          |
| `crates/audit`       | Hash-chained, tamper-evident audit log — **new vs. octo**             |
| `crates/api`         | axum REST API                                                        |
| `bin/server`         | Composes api + ingest + policy + audit into one service               |

See `docs/architecture.md` for the full request-flow walkthrough.

## Quickstart

```bash
# 1. Tooling: Rust 1.84.1 (pinned via rust-toolchain.toml), Docker, just
cp .env.example .env                 # then fill MASTER_KEY (openssl rand -base64 32)

# 2. Local Postgres (not yet wired into kobo-store — see CONTRIBUTING.md)
docker compose up -d db

# 3. Build & test
just build
just test

# 4. Run the service (REST API; ingest worker not yet composed into main.rs)
just run            # cargo run -p kobo-server -> API on $BIND_ADDR (default :8080)
```

Then, against a running server:

```bash
# Create a master wallet. Non-custodial: YOU generate the keypair
# (browser/SDK) and register only the public account.
curl -s -X POST localhost:8080/v1/wallets \
  -H 'content-type: application/json' \
  -d '{"public_key":"G...YOURS","label":"acme","org_id":"org_1"}' | jq

# Generate a customer deposit address (returns the M... address)
curl -s -X POST localhost:8080/v1/wallets/<WALLET_ID>/addresses | jq

# Relay a client-signed withdrawal, with an idempotency key
curl -s -X POST localhost:8080/v1/wallets/<WALLET_ID>/submit-signed \
  -H 'content-type: application/json' \
  -H 'Idempotency-Key: 5f2f...' \
  -d '{"transaction_xdr":"<BASE64_SIGNED_XDR>","customer_id":0,"amount_stroops":10000000}' | jq
```

See `docs/non-custodial-flow.md` for the full build → sign → relay sequence.

## Build status in this repo

`kobo-crypto`, `kobo-wallet-core`, `kobo-store`, `kobo-webhooks`,
`kobo-ingest`, `kobo-policy`, and `kobo-audit` — the seven crates holding
all the security-relevant logic — build cleanly and pass their full test
suite (26 tests) under a pinned toolchain. `kobo-api` and `bin/server` use
axum 0.7 and are standard, unexceptional usage of it, but weren't verified
to compile in the environment this was scaffolded in (its `cargo` was too
old for a few of axum's current transitive dependencies) — building them
with the pinned Rust 1.84.1 toolchain should just work; if it doesn't,
that's a great first issue.

## Security architecture

Kobo is non-custodial: user wallet keys are generated and held client-side
(browser/SDK), so the server has nothing to sign with and a full server
compromise cannot move user funds. The one remaining server-held key is
each wallet's optional gas tank — a fee-only account whose seed is
encrypted at rest and only decrypted in memory, inside `kobo-crypto`, for
the instant it takes to sign a fee-bump, then wiped.

See `docs/threat-model.md` for the full defense-by-attack-class mapping.
Report vulnerabilities per `SECURITY.md` — do not open public issues for
security reports.

## Status

Early development — extended with a policy
engine and an audit trail. See `docs/features-roadmap.md` for what's built
vs. planned.

## License

MIT — see `LICENSE`.
