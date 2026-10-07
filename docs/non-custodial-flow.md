# Build -> sign -> relay

Kobo never holds a customer's private key. The full withdrawal sequence:

1. `GET /v1/wallets/:id/signing-info` -> sequence number, network passphrase,
   base fee.
2. Client builds the transaction and signs it locally (browser/SDK/hardware
   wallet).
3. `POST /v1/wallets/:id/submit-signed` with `{ "transaction_xdr": "..." }`
   and an `Idempotency-Key` header.
4. Kobo validates, checks `kobo-policy` limits, optionally wraps in a
   fee-bump signed by the wallet's gas tank, records the decision in
   `kobo-audit`, and relays to Horizon/Soroban RPC.

There is no `POST /withdraw` — the server has no key to sign a customer
transaction with, so that route does not exist.
