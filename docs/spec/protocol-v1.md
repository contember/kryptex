# Kryptex protocol version 1

Status: frozen implementation specification for protocol version 1.

This document defines the byte-level client protocol and the server state transitions for version 1. An incompatible change requires a new protocol version after this document is frozen.

## Constants and primitives

- Random values: `crypto.getRandomValues`.
- Hash and HMAC: SHA-256 and HMAC-SHA-256.
- KDF: HKDF-SHA-256.
- Content AEAD: AES-256-GCM with a fresh 12-byte nonce and 16-byte tag.
- Passphrase KDF: Argon2id version `0x13`, `m=65536 KiB`, `t=3`, `p=1`, 32-byte output, and a fresh 16-byte salt.
- Public-key encryption: RFC 9180 base mode with DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, and AES-256-GCM.
- Text: strict UTF-8 without trimming or Unicode normalization.
- Integer encoding: unsigned big-endian.
- External binary encoding: RFC 4648 section 5 base64url, except for a human-entered second key. Canonical input uses only the URL alphabet, has no `=`, whitespace, or standard Base64 `+` and `/`, and has zero unused pad bits.
- Canonical JSON: RFC 8785 JSON Canonicalization Scheme (JCS), restricted to the shapes below. Numbers and `null` are forbidden.

Implementations must reject unsupported versions, suites, modes, reserved bits, invalid lengths, trailing bytes, malformed UTF-8, duplicate JSON keys, and non-canonical encodings. Eight-byte timestamps are unsigned integers and must not exceed `Number.MAX_SAFE_INTEGER`. Decrypted strings are rendered as text, never HTML or Markdown.

## Domain separation and HKDF

Labels are the exact UTF-8 bytes shown here, without an implicit terminator:

```text
kryptex/v1/send/locator
kryptex/v1/send/master/none
kryptex/v1/send/master/passphrase
kryptex/v1/send/master/random-factor
kryptex/v1/send/content-key
kryptex/v1/send/retrieve-token
kryptex/v1/send/manage-token
kryptex/v1/request/write-master/none
kryptex/v1/request/write-master/passphrase
kryptex/v1/request/write-master/random-factor
kryptex/v1/request/schema-key
kryptex/v1/request/write-token
kryptex/v1/request/owner-token
kryptex/v1/request/hpke-keypair
kryptex/v1/request/response
kryptex/v1/create-permit/locator
kryptex/v1/create-permit/token
kryptex/v1/create-permit/issuance
kryptex/v1/rate-limit-locator
```

The server capability tag prefix is separate from this label list: it is the 32 ASCII bytes `kryptex/v1/server-capability-tag` followed by one byte `0x00`.

HKDF helpers are:

```text
Extract(label, ikm) = HKDF-Extract(SHA-256(UTF8(label)), ikm)
Expand(prk, label, length) = HKDF-Expand(prk, UTF8(label), length)
```

All seed and factor inputs below are exactly 32 bytes, so concatenation is unambiguous.

## Factor modes

| ID | Mode | Factor input |
| --- | --- | --- |
| 0 | none | 32 zero bytes |
| 1 | passphrase | 32-byte Argon2id output |
| 2 | random factor | 32 random bytes transmitted independently |

Passphrases must contain 12 through 256 UTF-8 bytes. Creation requires an exact second entry. Clients do not trim or normalize either entry. The UTF-8 passphrase is Argon2 password `P`, the 16-byte bundle salt is Argon2 salt `S`, and optional secret `K` and associated data `X` are empty byte strings. The salt and fixed Argon2id parameters are carried in the link fragment.

The random factor is encoded from its 256 bits in most-significant-bit order with the Crockford Base32 alphabet `0123456789ABCDEFGHJKMNPQRSTVWXYZ`. Four zero bits pad the final five-bit group. Its canonical display is 52 uppercase characters grouped as four groups of 13 with ASCII hyphens. Input is case-insensitive, may contain hyphens only at canonical group boundaries, maps `O` to `0` and `I` or `L` to `1`, rejects `U` and whitespace, requires zero padding bits, and must decode to exactly 32 bytes. It contains no resource identifier or checksum.

## Send key schedule

The sender generates a 32-byte send seed `S`, a 32-byte management seed `M`, and factor input `F`.

```text
locatorPrk = Extract("kryptex/v1/send/locator", S)
locator = Expand(locatorPrk, "kryptex/v1/send/locator", 16)

masterPrk = Extract("kryptex/v1/send/master/<factor-mode>", S || F)
contentKey = Expand(masterPrk, "kryptex/v1/send/content-key", 32)
retrieveToken = Expand(masterPrk, "kryptex/v1/send/retrieve-token", 32)

managePrk = Extract("kryptex/v1/send/manage-token", M)
manageToken = Expand(managePrk, "kryptex/v1/send/manage-token", 32)
```

`<factor-mode>` is exactly `none`, `passphrase`, or `random-factor` from the table. The server receives derived values only and stores HMAC tags of tokens, never raw tokens.

## URL fragments and bundles

Paths contain no locator, capability, or key material:

```text
Recipient:  https://host/s#<recipient-bundle>
Management: https://host/m#<management-bundle>
Write:      https://host/r#<write-bundle>
Pickup:     https://host/i#<pickup-bundle>
```

Every bundle is canonical unpadded base64url over:

```text
magic       4 bytes  ASCII "KXB1"
kind        1 byte
version     1 byte   1
bodyLength  2 bytes
body        bodyLength bytes
```

The only valid bodies are:

| Kind | Meaning | Exact body | Length |
| --- | --- | --- | --- |
| 1 | send recipient | `S[32] || factorMode[1] || salt[16] || serverExpiresAt[8]` | 57 |
| 2 | send management | `locator[16] || M[32] || serverExpiresAt[8]` | 56 |
| 3 | request write | `R[16] || W[32] || factorMode[1] || salt[16] || recipientPublicKey[32] || serverExpiresAt[8]` | 105 |
| 4 | request pickup | `R[16] || O[32] || serverExpiresAt[8]` | 56 |

`salt` is all zero bytes unless `factorMode=1`; clients reject a nonzero salt in every other mode before derivation. `serverExpiresAt` is the Unix-seconds value returned by successful creation. The bundle timestamp is untrusted until it matches server response metadata or an authenticated envelope constraint. The client copies the fragment into memory and synchronously calls `history.replaceState` with the generic path before parsing or rendering any secret-related UI. It never writes fragment bytes to persistent browser storage.

## AES encrypted envelope `KXE1`

Send content and request schemas use:

```text
magic             4 bytes  ASCII "KXE1"
suite             1 byte   1 = AES-256-GCM
contentMode       1 byte   1 = send, 2 = request schema
factorMode        1 byte
flags             1 byte   zero
clientNotAfter    8 bytes  Unix seconds
maxRetrievals     2 bytes
schemaDigest      32 bytes
nonce             12 bytes
ciphertextAndTag  remaining bytes
```

The 62-byte header through `nonce` is AES-GCM additional authenticated data. The plaintext is exactly one allowed bucket:

```text
payloadLength  4 bytes
payload        payloadLength bytes
padding        cryptographically random bytes
```

Allowed plaintext bucket lengths are 4096, 16384, 65536, 262144, and 1048576 bytes. The smallest fitting bucket is mandatory. `ciphertextAndTag` is therefore one allowed bucket plus 16 bytes. The maximum `KXE1` length is 1048654 bytes.

`ciphertextAndTag` is AES-GCM ciphertext followed by its 16-byte tag.

Mode invariants are:

| Mode | factorMode | maxRetrievals | schemaDigest | Payload |
| --- | --- | --- | --- | --- |
| send | configured mode | 1 through 10 | 32 zero bytes | send text or fields |
| request schema | configured mode | 0 | `SHA-256(payload)` | request schema |

After authenticated decryption, clients require recipient-bundle `factorMode` to equal send-envelope `factorMode`, and write-bundle `factorMode` to equal schema-envelope `factorMode`. For a request schema, `payload` is the exact JCS schema bytes and the digest covers those bytes. The writer recomputes that digest before using the schema and compares the public key in the decrypted schema with the public key in the write bundle. The owner recomputes the schema digest after pickup. Every mismatch is fatal.

Clients reject decrypted content after `min(clientNotAfter, serverExpiresAt)` using the matching bundle value. The server independently enforces its stored expiry.

## HPKE response envelope `KXR1`

Write-once responses use a distinct container:

```text
magic             4 bytes  ASCII "KXR1"
suite             1 byte   1 = X25519/HKDF-SHA256/AES-256-GCM
flags             1 byte   zero
reserved          2 bytes  zero
clientNotAfter    8 bytes  Unix seconds
schemaDigest      32 bytes
encLength         2 bytes  32
ciphertextLength  4 bytes
enc               32 bytes
ciphertext        ciphertextLength bytes
```

The HPKE parameters are:

```text
info = UTF8("kryptex/v1/request/response") || R[16] || schemaDigest[32]
aad  = exact KXR1 bytes from magic through enc
```

HPKE supplies its own nonce. No application nonce is serialized. Encryption creates one fresh `SetupBaseS` context and calls `Seal(aad, plaintext)` exactly once at sequence number zero; `enc` and the returned `ct` are stored. Pickup creates the matching fresh `SetupBaseR` context and calls `Open` exactly once. The HPKE plaintext uses the same four-byte payload length and mandatory bucket padding as `KXE1`. `ciphertextLength` must equal one allowed bucket plus the 16-byte AEAD tag. The maximum `KXR1` length is 1048678 bytes. `clientNotAfter` must equal the request schema value. The receipt digest is SHA-256 over the exact complete `KXR1` bytes stored in R2.

## Canonical payloads

Every listed key is mandatory, including `help`. Additional keys are forbidden at every object level. Empty optional text is represented by `""`, never by omission or `null`. The only version 1 payload shapes are:

```json
{"kind":"text","text":"..."}
```

```json
{"fields":[{"concealed":true,"label":"...","value":"..."}],"kind":"fields"}
```

```json
{"fields":[{"help":"...","id":"a1b2c3d4","label":"...","required":true,"type":"secret"}],"kind":"request-schema","recipientPublicKey":"<unpadded-base64url-32-bytes>","title":"..."}
```

```json
{"answers":[{"id":"a1b2c3d4","value":"..."}],"kind":"request-response","schema":<exact-request-schema-object>}
```

Validation grammar:

| Payload or object | Exact keys | Rules |
| --- | --- | --- |
| send text | `kind`, `text` | `kind="text"`; `text` is 1 through 262144 UTF-8 bytes. |
| send fields | `fields`, `kind` | `kind="fields"`; `fields` contains 1 through 32 send-field objects. |
| send field | `concealed`, `label`, `value` | `concealed` is a boolean; `label` is 1 through 120 UTF-8 bytes; `value` is 1 through 262144 UTF-8 bytes. |
| request schema | `fields`, `kind`, `recipientPublicKey`, `title` | `kind="request-schema"`; `title` is 1 through 120 UTF-8 bytes; `fields` contains 1 through 32 schema-field objects; `recipientPublicKey` is canonical base64url decoding to 32 bytes. |
| schema field | `help`, `id`, `label`, `required`, `type` | `id` matches `[a-z0-9]{8,32}` and is unique; `label` is 1 through 120 UTF-8 bytes; `help` is 0 through 500 UTF-8 bytes; `required` is a boolean; `type` is `short`, `secret`, `long`, or `instruction`. An instruction has `required=false`. |
| request response | `answers`, `kind`, `schema` | `kind="request-response"`; `schema` is deeply equal to the valid decrypted request schema; `answers` follows the rules below. |
| answer | `id`, `value` | `id` equals one non-instruction schema ID; `value` is 0 through 262144 UTF-8 bytes. A required field has a nonempty value. |

Answers appear exactly once and in schema order for every non-instruction field. Instruction fields have no answer. An optional unanswered value is `""`. The response carries the exact schema object so pickup can reconstruct trusted labels. Its nested recipient public key must equal the write bundle key. The whole JCS payload plus its four-byte length must fit the smallest mandatory envelope bucket.

Encryptors and decryptors enforce this grammar. A malicious creator can bypass semantic limits because the server cannot inspect ciphertext; conforming recipients reject the decrypted payload. The server can enforce only clear envelope mode, encoded length, expiry, and release policy.

## Request key schedule

The owner generates a random 16-byte request locator `R`, a 32-byte write seed `W`, a 32-byte owner seed `O`, and factor input `F`.

```text
writePrk = Extract("kryptex/v1/request/write-master/<factor-mode>", W || F)
schemaKey = Expand(writePrk, "kryptex/v1/request/schema-key", 32)
writeToken = Expand(writePrk, "kryptex/v1/request/write-token", 32)

ownerPrk = Extract("kryptex/v1/request/owner-token", O)
ownerToken = Expand(ownerPrk, "kryptex/v1/request/owner-token", 32)
hpkeIkm = Expand(ownerPrk, "kryptex/v1/request/hpke-keypair", 32)
recipientKeyPair = HPKE.DeriveKeyPair(hpkeIkm)
```

The write bundle contains the public key. The pickup bundle contains `O`. The HPKE private key never reaches the service.

## Server capability tags

The Worker has a versioned 32-byte secret HMAC key and key ID. It stores the key ID and this tag for each presented capability:

```text
HMAC-SHA256(
  serverKey,
  ASCII("kryptex/v1/server-capability-tag") || 0x00 ||
  resourceKind[1] || capabilityKind[1] || locator[16] || token[32]
)
```

Resource kind is `1=send`, `2=request`, `3=create-permit`. Capability kind is `1=retrieve/write`, `2=manage/owner`, `3=create`. Verification reconstructs the exact input and uses `crypto.subtle.verify`. Key rotation retains old keys until every resource using them has expired.

## Candidate-object creation

R2 and Durable Object storage do not form one transaction. Every send, request schema, and submitted response uses this sequence:

1. Validate syntax, policy, clear envelope header, exact length, and creation permit where required.
2. Use the immutable 16-byte attempt ID supplied by a public create request, or generate one for an internal submit attempt, and generate a fresh random R2 candidate key. Neither is derived from the locator.
3. Put the exact bytes under that candidate key.
4. Run an idempotent Durable Object `init-if-empty` or state CAS with the attempt ID. It stores the attempt ID, candidate key, SHA-256 digest, exact byte length, tags, policy, and state and returns `committed_same_attempt` or `definitive_not_committed`. Existing state for another attempt and an expired settlement deadline are definitive non-commits.
5. On a transport error, retry the same operation with the same attempt ID. Existing state for that attempt returns `committed_same_attempt`. Delete this attempt's candidate only after `definitive_not_committed`. On an unresolved exception or timeout, leave it for a later probe or lifecycle cleanup.

A crash before step 4 can leave only an unreachable candidate. A failed delete after a definitive loss also leaves only an unreachable candidate. The R2 lifecycle rule removes either case. A committed state always names the winning object and is never deleted by an ambiguous caller. All reads verify stored length and digest before release.

Public send and request creation also carry `settleNotAfter`. Their init transaction compares its own integer Unix time and must return `definitive_not_committed` when `serverNow > settleNotAfter`. Internal retries preserve both attempt ID and deadline.

Send and request status capture `stateCheckedAt = floor(Date.now() / 1000)` inside the same locator Durable Object transaction as the authoritative state read and return it on success and generic unavailable. A status result with `stateCheckedAt > settleNotAfter` settles a lost create response: existing state is success; unavailable can no longer be followed by that attempt committing. HTTP response-creation time is not a substitute for `stateCheckedAt`.

Initialization and expiry shortening atomically commit state and `setAlarm(serverExpiresAt * 1000)` using `ctx.storage.transaction`. The transaction closure contains only deterministic Durable Object storage operations and no WebCrypto, R2, or other network I/O. Release counters that do not change the alarm may use `transactionSync`.

## Authentication backoff

Three controls apply:

1. An approximate edge limiter keys on client network identity and route before Siteverify, Argon2-triggering flows, or R2 work. It is an abuse and cost control, not a security invariant.
2. Bearer-resource routes also apply an approximate limiter keyed by the blinded locator tag defined below. This prevents one known locator from bypassing the coarse network limiter without exposing the locator to the limiting service.
3. Every resource Durable Object persists an exact authorization lease and failure backoff. A synchronous reservation rejects with generic `429` when `authBusyUntil > nowMs` or `nextAuthAt > nowMs`; otherwise it records a random attempt ID and `authBusyUntil = nowMs + 5000`. Only that attempt may finish verification. Failure increments a counter saturated at 8 and sets `nextAuthAt = nowMs + min(250 * 2^(count - 1), 30000)` milliseconds. Success clears the count, attempt ID, and both timestamps. An abandoned reservation becomes available after five seconds.

Both external limiters are approximate abuse and cost controls. A limiting-binding failure fails open and does not replace authorization. The persisted per-resource authorization lease and backoff remain fail closed and are the security control for online capability guesses.

This serializes capability guesses per resource even when `crypto.subtle.verify` yields the input gate. A failed verification itself returns the generic unavailable response; calls during the resulting delay return generic `429`.

Any external approximate locator key is the full canonical base64url tag:

```text
HMAC-SHA256(
  rateLimitKey,
  ASCII("kryptex/v1/rate-limit-locator") || 0x00 ||
  resourceKind[1] || locator[16]
)
```

`rateLimitKey` is a separate versioned 32-byte Worker secret.

## Send release state machine

`GET /s` returns only the application shell. An explicit POST release uses this ordering inside the per-resource Durable Object:

1. Reject malformed input before storage access and apply locator-keyed backoff before any existence-dependent response.
2. Read immutable state generation, HMAC key ID, and stored retrieve tag.
3. Await `crypto.subtle.verify` outside any synchronous transaction. Stop on failure.
4. Read and buffer the named R2 object. Verify its exact stored length and digest.
5. In one storage transaction, recheck generation, active state, expiry, tag identity, object identity, and remaining count. Decrement once. If zero, set state to `exhausted`, retain the object as pending cleanup, and atomically move the single alarm to immediate cleanup. The final transition uses `ctx.storage.transaction`; other decrements use `transactionSync`.
6. Return buffered bytes only when the transaction succeeds. For the final release, attempt R2 deletion before returning. Whether deletion succeeds or fails, return the already-committed buffer. On success, clear cleanup metadata and restore the expiry alarm atomically. On failure, retain the key for the early cleanup alarm without reopening release.

At most the configured number of concurrent calls pass step 5. A response lost after step 5 still consumes a release. Version 1 has no retry lease.

The `exhausted` tombstone retains only policy, management tag, terminal state, and cleanup metadata until the original expiry. It never retains ciphertext after successful deletion.

## Request submission and pickup state machine

Schema fetch reads immutable tag and generation, verifies the write token asynchronously, buffers and verifies the schema object, then synchronously rechecks generation, tag identity, object identity, `waiting` state, and expiry before return. It does not change state. Submission uses:

1. Authenticate against a snapshot of the immutable write tag and generation.
2. Validate `KXR1`, upload it to a fresh candidate key, and compute its exact length and digest.
3. In a storage transaction, recheck generation, tag identity, `waiting` state, and expiry, then perform the idempotent attempt CAS to `submitted` and store candidate metadata.
4. A loser deletes only its own candidate. After the CAS, schema fetch and further submit calls return unavailable.

The writer computes and displays the receipt digest locally. A server-returned copy is only a comparison aid, not proof of service behavior.

API encoding of a receipt is canonical unpadded base64url over all 32 digest bytes. Human display uses all 64 uppercase hexadecimal digits in eight groups of eight separated by spaces. Comparison uses every digit and should occur through a channel independent of the write link.

Pickup first authenticates the owner token, buffers and verifies the stored response, then rechecks generation, `submitted` state, expiry, tag identity, and object identity in a storage transaction before changing state to `picked_up`, retaining both objects as pending cleanup, and moving the alarm to immediate cleanup. It attempts both deletes before returning. Whether deletion succeeds or fails, it returns the already-committed buffer. Success clears cleanup metadata and restores the expiry alarm; failure leaves the early retry scheduled and never reopens pickup. The `picked_up` tombstone remains until expiry.

Owner status while `waiting` does not consume pickup. Owner status after submission does not release ciphertext. Management, owner, and permit operations likewise verify capability tags outside `transactionSync`, then synchronously recheck the immutable tag and generation before reading or changing authoritative state.

## Revocation, shortening, and expiry

Management or owner capabilities may revoke or shorten, but never extend, expiry. Every state-changing transaction rechecks the authenticated immutable tag and generation.

Revocation changes active state to `revoked`, records every named object as pending cleanup, and moves the alarm to immediate cleanup in one storage transaction before any R2 await. It then attempts idempotent deletes. Success clears cleanup metadata and restores the expiry alarm; failure retains the early retry. Logical revocation succeeds in either case and never reopens access. The authenticated terminal tombstone remains until expiry. A release already buffered but not yet committed fails its final state transaction.

Each state stores `serverExpiresAt` and optional `nextCleanupAt`. Before expiry, its one Durable Object alarm uses `min(serverExpiresAt * 1000, nextCleanupAt ?? serverExpiresAt * 1000)`.

When an alarm runs before expiry, it only retries pending idempotent R2 deletes. It does not change the terminal state. Success clears `nextCleanupAt` and the cleanup-failure count and restores the expiry alarm. Failure increments a counter saturated at 8 and uses `cleanupDelayMs = min(2000 * 2^(count - 1), 300000)`. It atomically retains cleanup metadata and schedules `min(nowMs + cleanupDelayMs, serverExpiresAt * 1000)`; if rescheduling fails, the handler throws so platform retry applies.

At or after expiry, the alarm first changes state to `expired`, then performs every pending or named R2 delete. It calls `deleteAll()` only after every delete succeeds. An object-delete or `deleteAll()` failure keeps the expired state, sets `nextCleanupAt = nowMs + cleanupDelayMs`, and schedules exactly `nextCleanupAt` without taking a minimum against the past expiry. Request handlers independently deny access from stored expiry and can initiate this same cleanup path when an alarm is delayed. The Worker compatibility date must be at least `2026-02-24` so `deleteAll()` also deletes alarms.

An R2 lifecycle rule based on the maximum supported lifetime plus an operational margin is a cleanup backstop, not the access-control clock.

## Protocol and server limits

Client-enforced decrypted payload limits are defined by the grammar above: at most 32 fields, 120-byte titles and labels, 500-byte help, and 262144-byte individual values.

Server-enforceable limits are:

- Allowed TTL: 15 minutes, 1 hour, 8 hours, 1 day, 3 days, or 7 days.
- Send releases: 1 through 10.
- Request writes and pickups: exactly 1.
- Encoded envelope type and mode: `KXE1` send or request schema, and `KXR1` request response.
- Maximum exact envelope lengths: 1048654 bytes for `KXE1` and 1048678 bytes for `KXR1`.

`serverNow`, `clientNotAfter`, and `serverExpiresAt` are integer Unix seconds; clients and the server compute current seconds as `floor(millisecondsSinceEpoch / 1000)`. The server accepts only:

```text
serverNow + selectedTTL - 300 <= clientNotAfter
clientNotAfter <= serverNow + selectedTTL + 300
serverExpiresAt = min(clientNotAfter, serverNow + selectedTTL)
```

Clients should use server time returned by the create-permit status response. Server authorization never relies on locator secrecy.

## HTTP invariants

- GET and HEAD never consume or authorize a capability.
- Tokens appear only in POST bodies or the short-lived create-permit cookie, never URLs.
- Every API response uses `Cache-Control: no-store` and `Referrer-Policy: no-referrer`.
- Request bodies, capabilities, locators, fragments, ciphertext, and plaintext are never logged.
- All bearer endpoint failures caused by missing, expired, exhausted, revoked, unauthorized, or wrong-state resources are indistinguishable.
- Rate limiting is applied before existence-dependent behavior and keyed by a blinded representation of the supplied locator.
- Browser API requests require the configured exact `Origin`; state-changing requests also require an expected Fetch Metadata context when those headers are present.

## Required vectors

The checked-in contract at `vectors/v1/` covers every factor mode, all four bundle kinds, both `KXE1` modes, `KXR1`, JCS payloads, key schedules, capability tags, bucket boundaries, malformed encodings, cross-container mismatches, and wrong-factor failures. Crypto and web implementations must consume the same vector files.
