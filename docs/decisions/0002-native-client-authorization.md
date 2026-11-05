# ADR 0002: Long-lived authorization for native clients

Status: proposed. The owner chooses an option before any spec, protocol, or server change.

## Context

Every `kryptex request create` and `kryptex send create` starts a [browser pairing](../spec/api-v1.md#browser-pairing-for-native-clients) and returns `action: pair`. A person must open `/pair`, pass Turnstile, and approve the user code before the CLI receives one single-use creation permit. A pairing expires 600 seconds after it starts, and the permit 1,800 seconds after approval. An agent that runs unattended therefore stops at every transfer until a person with a browser approves it.

### What pairing protects today

Pairing exists for one reason: a native client cannot run Turnstile, and creation requires a Turnstile-backed permit. Checked against each property it could plausibly carry:

| Property | Does pairing provide it? |
| --- | --- |
| Confidentiality of content, keys, or capabilities | No. The CLI generates `R`, `W`, `O`, `S`, `M`, and the second key locally. The permit is not bound to the transfer it funds. No adversary row in the threat model relies on pairing for secrecy. |
| Authentication of a person or machine | No. The service has no accounts. Approval proves that someone passed Turnstile and clicked approve, not who. |
| Attribution | No. Permits are unlinkable to people, and the service collects no identifiers by design. |
| Binding a request to its owner's key | No. The owner key never leaves the CLI, and pairing happens before the key exists. |
| Protection against phishing with write links | No. Anyone can create the same request form in a browser after one Turnstile solve. |
| Abuse and cost control | **Yes.** It is the only per-creation control on the native route. One human Turnstile solve funds one resource, so the native route cannot bypass the gate that the web client passes. |

A side effect is that a person notices each creation. This is not a control inside the [CLI boundary](../spec/cli-v1.md#security-boundary): a hostile agent is out of scope, and every transfer still reaches a person at hand-over, because the write link or recipient link has to be delivered to someone.

Without the permit, the remaining controls on creation are the [edge limiters](../spec/protocol-v1.md#authentication-backoff), which are approximate and fail open, and the policy limits: an envelope of at most 1,048,654 bytes kept for at most 30 days. The service cannot inspect what it stores.

### State pairing creates

- Server: a pairing Durable Object per user code (poll-token tag, expiry, and after approval the request ID, issuance key ID, and permit expiry, kept until the permit expires), a request-ID Durable Object, and a permit Durable Object.
- CLI: a `pairing` phase in each operation record (poll token, user code), then the permit in the `creating` phase.
- Transcript: one pairing link and user code per operation.

## Decision drivers

1. After one setup step, an unattended agent creates transfers without a browser.
2. No change to confidentiality, protocol version 1 key schedules, bundles, envelopes, or test vectors.
3. Abuse controls that are the only bound stay fail closed.
4. No accounts and no new identifiers.
5. A person can revoke the authorization without access to the machine that holds it.

## Options

### A. Paired device grant

The person pairs once per machine and service origin. Approval creates a revocable **device grant** instead of a single permit. The CLI keeps a device token and uses it to mint a fresh single-use permit right before each creation. The token works like an OAuth refresh token and the permit like an access token: creation routes, permits, and resources stay exactly as they are.

Mechanics:

- The CLI generates a random 16-byte device locator and a 32-byte device token, and starts a pairing that carries them.
- `/pair` runs Turnstile and records the approval, but neither mints a permit nor creates device state yet. It sets a single-use HttpOnly claim cookie bound to the pairing and performs a full-page navigation to a Turnstile-free confirmation page. This repeats the `/gate` to `/send` pattern, because the device management capability is a protected asset and Turnstile must not run in a document that holds one. Today's rule that the pairing page sets no cookie changes accordingly.
- The confirmation page asks: **this transfer only** (today's behaviour) or **this machine until a date** (1, 7, 30, or 90 days). For a device grant it generates a random 32-byte management token in the browser, sends it with the claim, and shows a **device management link** `/d#…` once, with the same copy and saved confirmation as other links.
- The device Durable Object stores the device-token tag, the management-token tag, expiry, revoked state, a quota counter, and the times of the most recent mints. It never records which resources its permits created.
- `POST /api/v2/devices/permits` (native only) takes the locator, the device token, and a random request ID. The Durable Object checks the tag under the existing authorization lease and backoff, checks expiry and revocation, and charges the quota once per request ID. The Worker derives the permit from the issuance keyring and the request ID exactly as Turnstile issuance does, so a retry after a lost response returns the same permit and no new construction is introduced.
- `POST /api/v2/devices/status` and `POST /api/v2/devices/revoke` accept either the device token or the management token. Status returns state, expiry, remaining quota, and mint times.
- The device management page shows that status and offers revoke, following the shared fragment lifecycle.
- The quota is enforced inside the device Durable Object and fails closed. Proposal: 50 creations per rolling 24 hours.

Expiry and scopes:

- The grant has a fixed expiry chosen at approval, at most 90 days. Minting a permit does not extend it. A sliding expiry would let a leaked token live forever while it is used.
- No scopes. Send and request creation have the same abuse and cost profile, so a scope that permits one and not the other bounds nothing. The quota and the expiry are the meaningful limits.
- No token rotation. A lost mint response would strand a rotated token, and the theft that rotation detects goes through the same-user boundary that the CLI does not defend. Mint times on the management page serve detection instead.

Threat-model impact:

| Adversary | Outcome |
| --- | --- |
| Starts a pairing and persuades someone to approve it as a device | Obtains a device grant: up to the quota per day until expiry or revocation, instead of one permit. This is the main regression. The confirmation page states the duration in plain words, offers **this transfer only**, and gives the person the management link. |
| Obtains a device token, for example from a backup or synced dotfiles | Mints permits up to the quota until expiry or revocation. Learns nothing about any transfer. |
| Obtains a device management link | Sees mint times and quota, and can revoke the grant, which only denies service to that machine. Cannot mint permits. |
| Reads an AI agent's transcript of CLI use | Sees a pairing code once per machine and grant period instead of once per operation. Approving someone else's pending pairing still funds only the CLI that holds the device token. |
| Operates the service | Can link creations made under one grant by mint timing. Learns no identifier and no content. Hiding timing and IP addresses is already a non-goal. |

One Turnstile solve now funds up to quota × lifetime creations, for example 1,500 at 50 per day for 30 days, instead of one. The edge limiter still applies to pairing and minting.

API and protocol changes:

- Additive routes under `/api/v2`, a device Durable Object class, and a `/d` page. Existing routes keep their meaning, and the one-permit pairing stays as **this transfer only**.
- New server capability-tag values: resource kind `5=device`, capability kinds `5=device-mint` and `6=device-manage`. This follows the precedent of resource kind `4=pairing`: no existing value changes meaning. Both tokens are random 32-byte values and use the 30-second backoff cap of non-guessable capabilities.
- The device management link gets its own path and its own versioned fragment grammar in the API spec, not a new `KXB1` bundle kind, so protocol version 1 stays frozen.
- No new key schedule. Device and management tokens are random, and permit derivation is the existing issuance derivation.

CLI and migration:

- A device file per origin, `devices/<sha256(origin)>.json` in the state directory, mode `0600`, under the existing directory ownership and permission checks. It holds the origin, locator, token, and expiry. It is never printed; `list` does not show it.
- New operations with a valid device file mint a permit with a request ID recorded before the call, then continue to `creating` without a `pairing` phase. The first `create` then returns `hand_over_write_link` directly.
- A missing, expired, or revoked device starts a pairing as today. A device rejected by the service is deleted locally.
- Records already in the `pairing` phase finish through the one-permit flow. The record schema gains a minting phase, which an older CLI cannot parse; this is a local downgrade limit, not a protocol change.
- New commands: `kryptex device status` and `kryptex device forget` (revoke, then delete the file).
- The agent instructions change step 4: pairing happens once per machine, and the person should choose a device grant when they want unattended use.

UX for an unattended agent: one approval per machine and grant period, which works from a phone. After that, creation needs no person. The only remaining human step is the hand-over that every transfer needs anyway. When the grant expires, the next `create` returns `action: pair`, as every `create` does today.

A smaller variant, **A-lite**, omits the confirmation page and management link: the scope choice moves into `/pair`, and revocation is only `kryptex device forget` plus expiry. It removes the web work and the claim cookie, but a person who loses the machine cannot revoke the grant before it expires.

### B. No permit for native creation

Native creation requests carry no permit. The service relies on the edge limiters, size and lifetime limits, and the short link lifetimes that already exist. Turnstile stays on the web gate.

Threat-model impact:

- Confidentiality: unchanged.
- The pairing rows disappear from the threat model: no pairing codes in transcripts, no approval phishing.
- The abuse assumption no longer holds. The native route bypasses the web gate entirely, so Turnstile protects nothing that a script cannot reach without it. Per client network and route, the edge limiter allows 120 creations per minute of up to about 1 MiB each, kept up to 30 days, and it fails open. A botnet multiplies that.
- This reopens anonymous bulk storage, the service as a free encrypted file drop, and bulk request forms on the service's domain. Domain reputation damage, such as phishing blocklists, would deny service to every user.
- Fail-closed per-client quotas would need a stored client identifier, which the observability rules forbid. Proof of work costs a botnet little.

API and protocol changes: creation routes accept native requests without `Kryptex-Create-Permit`; pairing routes and the `/pair` page can be retired after old CLIs age out. The simplest code of all options.

Migration: the CLI drops the `pairing` phase for new operations; in-flight records finish or are discarded.

UX: best. No human step besides the hand-over.

### C. Gate the human side instead of the creator

Native creation needs no permit, but a resource stays inactive until the writer or recipient passes Turnstile before using the link.

Rejected. The threat model requires retrieval and write routes to stay usable without Turnstile. The gate would come after storage, so it does not bound what an abuser stores. Unactivated resources still cost storage until they expire.

### D. Accounts with a device list

The person signs in, for example with a passkey, and sees and revokes all devices in one list.

Rejected. It introduces a person identifier, which the service avoids by design, and adds an authentication system, session handling, and account recovery. Option A's management link gives per-device status and revocation without an identity. A list across devices is not possible without accounts.

### E. Several permits per pairing

One approval returns N single-use permits.

Rejected. It only defers the pairing prompt. With a quota and an expiry, option A bounds the same abuse while removing the prompt for the whole grant period.

## Comparison

| | A. Device grant | B. No permit | Today |
| --- | --- | --- | --- |
| Human steps per transfer | Hand-over only | Hand-over only | Pairing and hand-over |
| Human steps per machine | One pairing per grant period | None | None |
| Creations per Turnstile solve | Up to quota × lifetime | Unbounded | 1 |
| Abuse bound | Fail-closed quota per grant, plus edge limiter | Edge limiter only, fails open | Turnstile per creation, plus edge limiter |
| Revocation by a person | Management link, CLI, expiry | Not applicable | Not applicable |
| Protocol version 1 change | None | None | None |
| Server work | Device object, 3 routes, confirmation and `/d` pages | Remove the permit check on native creation | None |

## Recommendation

**Option A, device grant.** Pairing buys no confidentiality, but it is the only thing that keeps the native route from being an anonymous, unbounded encrypted store with a public domain attached. Option A keeps one human Turnstile solve per machine and grant period, bounds abuse by a fail-closed quota, and gives the person a revocation handle, while removing the per-transfer prompt that blocks unattended agents.

Option B is acceptable only for a deployment whose operator accepts unbounded anonymous storage, for example a private instance behind an access proxy.

Choices for the owner:

1. Option A, A-lite, or B.
2. Grant lifetimes and the default. Proposal: 1, 7, 30, or 90 days; default 30.
3. Quota. Proposal: 50 creations per rolling 24 hours per grant.
4. Whether to keep **this transfer only** on the confirmation page. Proposal: yes; it is today's flow.

## Consequences

If option A is chosen:

- The threat model, API spec, CLI spec, and product flows are updated before code, including the regressed row for an approved phishing pairing.
- The Worker gains a device Durable Object class and a migration tag. Old CLIs keep working unchanged.
- The abuse assumption changes from one Turnstile solve per creation to one Turnstile solve per grant, bounded by quota and lifetime.
