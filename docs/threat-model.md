# Threat Model

| Attack class                         | Defense in Kobo                                                                 |
|---------------------------------------|-----------------------------------------------------------------------------------|
| Full server compromise                | User keys are never on the server — DB, backups, and RAM all lack them            |
| Stolen key backup                     | `encrypted_backup` is client-produced ciphertext; the server cannot decrypt it    |
| Gas-tank seed stolen from DB/backup   | AES-256-GCM, random nonce+salt; master key from KMS/env, never in the DB          |
| Seed/key leaked via logs or panic     | Secrets confined to `kobo-crypto`/`kobo-wallet-core`, wrapped in `Zeroizing`       |
| Signing-oracle abuse                  | No user key server-side — nothing to coerce into signing                          |
| Fee-bump abuse (sponsorship)          | Gas tank signs only the outer fee-bump envelope; per-tx cap + daily budget         |
| Deposit double-credit (reorg/replay)  | Credited only on `successful == true`, idempotent on `(tx_hash, op_index)`        |
| Submit-signed retried by a flaky client | `Idempotency-Key` header deduplicates relays server-side (new vs. octo)         |
| Velocity abuse (rapid drain via many small withdrawals) | `kobo-policy` enforces a rolling-window per-customer cap (new vs. octo) |
| Tampering with the relay decision log | `kobo-audit` hash-chains every entry to its predecessor (new vs. octo)           |
| Wrong-network signature               | Network bound as AES-GCM AAD — a testnet-sealed seed can't be opened as mainnet  |
| SSRF via webhook URL                  | Loopback/private/link-local targets rejected, IPv4 and bracketed IPv6            |
| SQL injection                         | Parameterized queries only, no string-built SQL                                  |

Amounts are integer stroops end-to-end — never floats.
