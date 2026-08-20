# ADR 0001: Durable Object authority with private R2 payload storage

Status: accepted.

## Context

Version 1 needs strict retrieval counters, write-once transitions, short-lived encrypted payloads, and cleanup without a central database scan.

Workers KV provides automatic key expiration but is eventually consistent and does not support atomic read-modify-delete. D1 supports atomic SQL but requires cleanup and exposes deleted rows through automatic Time Travel. SQLite-backed Durable Objects provide per-resource serialization and alarms, but storing ciphertext there couples payload retention to point-in-time recovery.

## Decision

Use one SQLite-backed Durable Object per send, request, or create permit as the state authority. Store encrypted envelopes in a private R2 bucket. Route all access through the Durable Object. Use alarms for precise cleanup and an R2 lifecycle rule as a maximum-retention backstop.

## Consequences

- Retrieval and write-once transitions are serialized per resource.
- R2 write, read, and delete visibility is globally strongly consistent.
- The application uses two storage products and must clean up partial creation failures.
- R2 writes use unique random candidate keys and attempt IDs followed by idempotent Durable Object `init-if-empty` or compare-and-swap. Ambiguous callers never delete candidates; only a definitive losing result permits best-effort deletion. R2 and Durable Object state are never described as one transaction.
- A network failure after a strict claim may consume the only retrieval.
- Final release, pickup, and revocation delete ciphertext but retain a small authenticated terminal tombstone until the original expiry.
- Each object multiplexes cleanup retry and expiry through one alarm scheduled at the earlier timestamp. Early cleanup never changes expiry state and restores the expiry alarm after success.
- R2 lifecycle is not the access-control clock and may run later than the requested expiry.
- The service promises logical unavailability and active-copy deletion, not immediate erasure from all provider backups.
