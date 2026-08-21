# Kryptex

Kryptex is a capability-based, end-to-end encrypted service for sending or requesting short-lived secrets without an account. Encryption and decryption run in the browser. The service stores encrypted envelopes and protocol state, not readable secret content or decryption keys.

> **Experimental — not production-ready.** The protocol and implementation have not completed an independent cryptographic review. The repository also has no tested production deployment. Do not use the current application for real secrets.

## Architecture

- A React client creates keys, encrypts content, derives capabilities, and removes secret URL fragments from the address bar before rendering a secret page.
- A Cloudflare Worker validates requests and serves the client. Plaintext, passphrases, second keys, link seeds, and content keys must never reach it.
- SQLite Durable Objects serialize retrieval, write-once, expiry, shorten, and revoke state.
- A private R2 bucket stores ciphertext. Durable Object alarms perform primary cleanup; a 31-day lifecycle rule is an orphan backstop.
- Cloudflare Turnstile runs only in an isolated creation gate. It is an abuse control, not part of encryption or capability authorization.

Compromise of the served browser code can expose secrets used after that compromise. A recipient can also retain plaintext after retrieval; expiry cannot take it back. See the [threat model](docs/spec/threat-model.md) for the full boundary.

## User flows

- **Send:** create an encrypted secret, share the `/s#…` recipient link, optionally send a second key through an independently secured channel, and retain or discard the `/m#…` management link.
- **Request:** define fixed fields, share the write-only, write-once `/r#…` link, optionally send a second key separately, and retain the `/i#…` pickup link.
- **Consume:** retrieval and pickup require an explicit consuming action. Loading a page or making a `GET` request does not consume a release or write capability.

The detailed state and retry rules are in [product flows](docs/spec/product-flows.md). The wire format is frozen in [protocol version 1](docs/spec/protocol-v1.md).

## Development

Install Bun 1.3.14, then follow [development and local-operation setup](docs/reference/development.md). The short path is:

```sh
bun install --frozen-lockfile
bun run dev
```

Local development also needs the environment files described in that guide. Do not deploy from a workstation. The repository intentionally has no deployment workflow or production deploy script.
