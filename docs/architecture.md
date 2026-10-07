# Architecture

Kobo is a Cargo workspace. All secret-handling is isolated in `kobo-crypto` and
`kobo-wallet-core`; every other crate only ever sees ciphertext, public keys,
or already-signed transaction envelopes.

| Crate              | Responsibility                                                        |
|---------------------|------------------------------------------------------------------------|
| `kobo-crypto`       | AES-256-GCM seal/open for the gas-tank seed (random nonce, zeroized)  |
| `kobo-wallet-core`  | StrKey (G.../M...) encode+decode, SEP-0005 derivation, fee-bump sign  |
| `kobo-store`        | Storage trait + in-memory impl now, Postgres/sqlx impl behind a flag  |
| `kobo-webhooks`     | HMAC-SHA256 signed outbound webhooks                                  |
| `kobo-ingest`       | Horizon payment streaming trait + durable-cursor deposit detection    |
| `kobo-policy`       | Per-customer velocity / spend-limit rules (new vs. octo)              |
| `kobo-audit`        | Hash-chained, tamper-evident audit log (new vs. octo)                 |
| `kobo-api`          | axum REST API + OpenAPI spec                                          |
| `bin/server`        | Composes api + ingest + policy + audit into one service               |

## Request flow: creating a deposit address

1. Client calls `POST /v1/wallets/:id/addresses`.
2. `kobo-wallet-core` assigns the next 64-bit customer id and encodes it into
   a muxed address (`M...`) against the wallet's one on-chain `G...` account.
   This is free and entirely off-chain — no funded account is created.
3. `kobo-store` persists the `(wallet_id, customer_id, muxed_address)` row.
4. The `G...` + numeric-memo fallback is returned alongside the `M...` address
   for senders that don't yet support muxed accounts.

## Request flow: relaying a signed withdrawal

1. Client fetches `GET /v1/wallets/:id/signing-info` (sequence, network
   passphrase, base fee) and builds + signs the transaction **entirely
   client-side**.
2. Client calls `POST /v1/wallets/:id/submit-signed` with the signed XDR and
   an `Idempotency-Key` header.
3. `kobo-api` checks `kobo-policy` (daily cap / velocity rules for that
   customer) before doing anything else.
4. `kobo-wallet-core` validates the envelope (v1, signature present, source
   matches wallet, op-type allowlist) — it never re-signs the inner
   transaction.
5. If the wallet has a gas tank configured, `kobo-crypto` briefly decrypts the
   gas-tank seed in memory, `kobo-wallet-core` signs the fee-bump envelope
   only, and the key is zeroized immediately after.
6. `kobo-audit` appends a hash-chained record of the relay decision before
   the transaction is broadcast.

See `docs/threat-model.md` for the full attack-surface breakdown and
`docs/deposit-model.md` for why muxed accounts remove the need for an
auto-sweep service entirely.
