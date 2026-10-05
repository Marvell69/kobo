# Contributing to Kobo

Thanks for looking at Kobo. This file exists partly for Drips Wave: it's
what turns a repo into something contributors can actually pick up work
from during a 7-day sprint.

## Local setup

```bash
cp .env.example .env
docker compose up -d db
just build
just test
```

`just check` runs `cargo check` + `clippy -D warnings` — CI (once wired,
see issue list below) will run the same thing, so it's worth running
locally before opening a PR.

## Code style

- `cargo fmt --all` before committing (`just fmt`).
- No `unwrap()`/`panic!()` inside `crates/crypto` or `crates/wallet-core` —
  those crates handle key material and must fail closed via `Result`.
- New public functions in `crates/policy` and `crates/audit` need at least
  one test covering the "deny"/"tamper-detected" path, not just the happy
  path — see the existing tests in those crates for the pattern.

## Pull request process

1. Fork, branch off `main`.
2. Keep PRs scoped to one crate where possible — it makes review and Wave
   point-scoring cleaner.
3. Reference the issue you're closing (`Closes #N`).
4. A maintainer reviews, merges, and (during an active Wave) marks the
   issue resolved so points are credited.

## Good first issues (seeded — label these on GitHub before applying to a Wave Program)

**Trivial (100 pts)**
- Add `#[non_exhaustive]` to public enums in `kobo-wallet-core` and
  `kobo-ingest` so adding a variant later isn't a breaking change.
- `kobo-policy`: add a `remaining_capacity()` helper so a client can show
  "you have X stroops left today" without triggering a denial first.
- Wire `just migrate` to a real `sqlx-cli` invocation once `crates/store`
  has migrations (see the Medium item below for the migrations themselves).

**Medium (150 pts)**
- Implement a Postgres-backed `Store` in `crates/store` behind a `postgres`
  feature flag, alongside the existing `InMemoryStore`, with migrations.
- Wire a real Horizon SSE client into `crates/ingest` behind the
  `CursorStore` trait, replacing the current stub.
- Add `Idempotency-Key` deduplication to `POST /v1/wallets/:id/submit-signed`
  in `kobo-api` — the header is already read but not yet acted on.
- Generate `/v1/openapi.json` from the actual route handlers (e.g. via
  `utoipa`) instead of the current static stub.

**High (200 pts)**
- Implement the SEP-41 Soroban token ingest listener referenced in
  `docs/deposit-model.md`.
- Implement real XDR envelope validation in `kobo-wallet-core`
  (`EnvelopeValidator`) using `stellar-xdr`, replacing the trait stub.
- Build the SEP-24 anchor deposit/withdraw flow stubbed in the roadmap.
- Add a multi-tenant RBAC layer (owner/admin/viewer) to `kobo-api`.

## Reporting a vulnerability

Don't open a public issue for security reports — see `SECURITY.md`.
