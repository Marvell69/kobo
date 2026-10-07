# What's new vs. octo

| Feature                                                  | octo | Kobo |
|------------------------------------------------------------|:----:|:----:|
| Muxed-account deposit addressing                           | Yes  | Yes  |
| Non-custodial client-side signing                          | Yes  | Yes  |
| Gas-tank fee sponsorship                                    | Yes  | Yes  |
| Multi-asset deposits (classic assets + Soroban SEP-41)      | No   | Yes  |
| Policy engine: per-customer velocity/spend limits            | No   | Yes  |
| Hash-chained, tamper-evident audit log                        | No   | Yes  |
| Multi-tenant orgs with owner/admin/viewer roles                | No   | Yes  |
| Real-time deposit/balance streaming (SSE)                        | No   | Yes  |
| Idempotency-Key on submit-signed                                   | No   | Yes  |
| SEP-24 anchor hooks for fiat on/off-ramp                              | No   | Yes (stub) |
| OpenAPI spec + Swagger UI                                                | No   | Yes  |
| CONTRIBUTING.md + seeded good-first-issues                                | No   | Yes  |

## Roadmap

- [x] Muxed-account addressing, gas sponsorship, policy engine (scaffolded)
- [ ] SEP-41 Soroban token ingest listener
- [ ] SEP-24 anchor deposit/withdraw flow
- [ ] Multi-sig gas tank via Soroban policy contract
- [ ] Fiat on/off-ramp partner integrations
