# Research notes

Status: source record for the version 1 architecture. Sources were checked on 2026-08-20.

## Storage decision

| Option | Useful property | Blocking limitation for Kryptex | Decision |
| --- | --- | --- | --- |
| Workers KV | Native key expiration | Reads are eventually consistent and KV has no atomic read-modify-write transaction. A stale read can violate strict release counts or write-once behavior. | Do not use on the authorization path. |
| D1 | SQL transactions and familiar queries | A shared database is unnecessary for no-login, per-resource state. Time Travel is always enabled and retains restorable history for 7 or 30 days, which conflicts with minimizing recoverable metadata. Cleanup also needs a scan or scheduled index. | Do not use in version 1. |
| SQLite Durable Objects | Per-object strong consistency, synchronous transactions, and alarms | R2 calls and WebCrypto are asynchronous and cannot join a SQLite transaction. Each object has one alarm, and alarm handlers require idempotent retry logic. | Use one object per send, request, or create permit for state only. |
| R2 | Strong read-after-write and delete consistency through Worker bindings | Lifecycle deletion is delayed and cannot enforce an exact access deadline. R2 and Durable Object state have no distributed transaction. | Use private R2 for encrypted envelopes with random candidate keys. |

The resulting protocol uploads a unique R2 candidate first and then performs a synchronous Durable Object compare-and-swap. Losing candidates are deleted by that attempt. Unreachable crash remnants are removed by a bucket lifecycle rule. Durable Object state is the access-control clock; lifecycle is only a cleanup backstop.

## Cloudflare findings

- [Workers KV consistency](https://developers.cloudflare.com/kv/concepts/how-kv-works/) documents eventual consistency, stale reads that can last 60 seconds or more, and the lack of atomic transactions.
- [D1 Time Travel](https://developers.cloudflare.com/d1/reference/time-travel/) is always on and supports restore to prior `DELETE` or `UPDATE` state for 7 days on Free and 30 days on Paid.
- [Durable Object concepts](https://developers.cloudflare.com/durable-objects/concepts/what-are-durable-objects/) describe the globally unique coordination point and its private, transactional, strongly consistent storage.
- [SQLite Durable Object storage](https://developers.cloudflare.com/durable-objects/api/sqlite-storage-api/) requires `transactionSync` callbacks to complete synchronously. The same page states that `deleteAll()` removes alarms with compatibility date `2026-02-24` or later.
- [Durable Object alarms](https://developers.cloudflare.com/durable-objects/api/alarms/) use Unix epoch milliseconds, execute at least once, and retry a thrown handler at most six times. Long-lived cleanup therefore catches downstream errors and explicitly schedules another alarm.
- [R2 consistency](https://developers.cloudflare.com/r2/reference/consistency/) covers strongly consistent reads, writes, metadata updates, listings, and deletes through bindings or the S3 API.
- [R2 lifecycle rules](https://developers.cloudflare.com/r2/buckets/object-lifecycles/) may remove an expired object within roughly 24 hours or later. They are unsuitable for precise authorization expiry.
- [Turnstile Siteverify](https://developers.cloudflare.com/turnstile/get-started/server-side-validation/) requires server validation. Tokens are single-use, expire after 300 seconds, and accept a UUID idempotency key for safe verification retries. Kryptex additionally verifies the expected hostname and action, then mints its own one-use permit.

## Cryptographic findings

- [RFC 9180](https://www.rfc-editor.org/info/rfc9180/) defines HPKE and the selected X25519, HKDF-SHA256, and AES-256-GCM suite. Base mode lets an anonymous writer encrypt to a request-specific recipient public key without learning the private key.
- [RFC 9106](https://www.rfc-editor.org/info/rfc9106/) defines Argon2id. Its memory-constrained recommendation uses 64 MiB and three passes. Version 1 fixes those costs and uses one lane for predictable browser support; this parameter choice still needs browser performance testing.
- [RFC 8785](https://www.rfc-editor.org/info/rfc8785/) defines deterministic JSON serialization. Version 1 further forbids numbers and `null` to keep the accepted payload subset small.
- AES-GCM nonces must never repeat under one key. Kryptex generates a new seed and key per resource and still generates a fresh 96-bit nonce for each AES envelope.
- URL fragments are processed client-side and are not sent in the HTTP request. This prevents ordinary server access logs from receiving link key material, but first-party JavaScript can still read it. The client therefore removes the fragment synchronously before rendering the flow.

## Limits of the result

This design protects stored ciphertext from a passive storage or API compromise when factor material remains separate. It does not protect a user who loads a malicious or compromised first-party web bundle. Server-enforced release counts are also not cryptographically provable against a malicious operator. A production launch requires an independent cryptographic and implementation review, dependency review, operational abuse testing, and browser compatibility testing.
