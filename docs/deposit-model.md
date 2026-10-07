# Why muxed accounts make this simple

A traditional "master wallet" WaaS deploys a funded on-chain account per
customer and sweeps funds back to a master account. Kobo skips that entirely
by using Stellar muxed accounts (`M...`):

- One real account (`G...`) plus a per-customer 64-bit id encoded into the
  address.
- Deposits to a customer's `M...` land directly in the master account and
  carry the id — so there is **no auto-sweep**, **no per-user XLM reserve**,
  and generating an address is **free and off-chain** (just assign the next
  id).
- For senders that don't yet support `M...` (some exchanges), Kobo also
  exposes the equivalent `G...` + numeric-memo form and attributes deposits
  by muxed id or memo id.

## Beyond octo: multi-asset deposits

Kobo extends this to attribute deposits across:
- The native asset (XLM)
- Any classic Stellar asset the master account trusts
- SEP-41 Soroban token contracts, via a separate ingest listener

Each deposit event carries an `asset` field so a single customer id can
receive stablecoins, XLM, or a Soroban token without a new address per asset.
