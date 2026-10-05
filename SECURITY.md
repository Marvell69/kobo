# Security Policy

Kobo is non-custodial: customer wallet keys are generated and held client-side.
The only plaintext key material the server ever touches is a wallet's optional
gas-tank fee key, confined to `kobo-crypto` + `kobo-wallet-core`.

## Reporting a vulnerability

Do not open a public issue. Email security@yourdomain.example with:

- A description of the issue and its impact
- Steps to reproduce
- Any relevant logs or PoC code

We aim to acknowledge reports within 48 hours.

## Scope

- The submit-signed relay path (transaction validation before broadcast)
- The gas-tank seal/open flow in `kobo-crypto`
- The policy engine's velocity-limit enforcement in `kobo-policy`
- Webhook signature generation in `kobo-webhooks`
