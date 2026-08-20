# Protocol vector tooling

This directory derives the static version 1 fixtures in `../../vectors/v1`.
The tooling is deliberately separate from the Kryptex packages. It uses
standards implementations instead of production Kryptex code.

## Pinned tools

- Bun 1.3.14
- Node.js Web Crypto and `node:crypto` from Node.js 24.4.0
- OpenSSL 3.5.3 (the Node.js crypto provider on the derivation host)
- `@hpke/core` 1.9.0
- `@hpke/common` 1.10.1 (locked transitive dependency)
- `hash-wasm` 4.12.0
- `@noble/hashes` 2.3.0
- `canonicalize` 4.0.0

The lockfile pins transitive npm dependencies. The checked-in fixtures are the
protocol contract; the generator is derivation evidence, not application code.

## Reproduce

From this directory:

```sh
bun install --frozen-lockfile
cpu-lease run -n 1 -- bun run generate
cpu-lease run -n 1 -- bun run check
```

`generate` rewrites only `vectors/v1/*.json`. `check` derives the values again,
compares every static fixture under both Node.js and Bun, and then performs
independent primitive checks:

- Node.js `node:crypto` output is compared with Web Crypto for SHA-256, HMAC,
  HKDF, and AES-256-GCM.
- `hash-wasm` Argon2id output is compared with `@noble/hashes` Argon2id.
- JCS output from `canonicalize` is compared with an independent restricted JCS
  serializer used only by the checker.
- HPKE encryption is opened again by a fresh recipient context.
- `@hpke/core` is checked against the published RFC 9180 base-mode vector for
  DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, and AES-256-GCM.

The checker does not import `derive.mjs`. It treats the static manifest entropy
and payload objects as inputs, then independently rebuilds every key schedule,
bundle, envelope, tag, permit, and receipt. It also executes every declared
negative case. Compact boundary vectors cover all five padding buckets without
checking in megabytes of ciphertext.

All fixture entropy is explicit. Sequential byte strings and deterministic
padding patterns are test inputs only. They are intentionally unsuitable for
real encryption.

## RFC 9180 provenance

The embedded HPKE conformance case is the base-mode case with `kem_id=32`,
`kdf_id=1`, and `aead_id=2` from the RFC 9180 test vector corpus:

- Corpus commit: `b1f7cb0cdeab6906c61b3d6574e8bdfdbe1cd3fb`
- `test-vectors.json` SHA-256:
  `61fc662f01996cd06d713dacf5e133167bd309a1f329442d53f1e21a47b3ede6`

```sh
curl -fsSL \
  https://raw.githubusercontent.com/cfrg/draft-irtf-cfrg-hpke/b1f7cb0cdeab6906c61b3d6574e8bdfdbe1cd3fb/test-vectors.json \
  -o /tmp/hpke-test-vectors.json
sha256sum /tmp/hpke-test-vectors.json
jq '[.[] | select(.mode==0 and .kem_id==32 and .kdf_id==1 and .aead_id==2)][0]' \
  /tmp/hpke-test-vectors.json
```

The expected recipient and ephemeral public keys, encapsulated key, and first
ciphertext are embedded in `derive.mjs`, so checking does not require network
access.
