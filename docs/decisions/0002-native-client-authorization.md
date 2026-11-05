# ADR 0002: Long-lived authorization for native clients

Status: accepted.

Decision: option A. Grant lifetimes 1, 7, 30, or 90 days; the CLI asks for 30 by default. Quota 50 creations per rolling 24 hours per grant. The confirmation page keeps **this transfer only**. Device grants are a new version of creation authorization: routes under `/api/v3/devices`, and device-minted permits presented as `v3.<P>`, so no existing `v2.` value changes meaning. The [HTTP API](../spec/api-v1.md#device-grants-creation-authorization-version-3) holds the specification.

## Context

Every `kryptex request create` and `kryptex send create` starts a [browser pairing](../spec/api-v1.md#browser-pairing-for-native-clients) and returns `action: pair`. A person must open `/pair`, pass Turnstile, and approve the user code before the CLI receives one single-use creation permit. A pairing expires 600 seconds after it starts, and the permit 1,800 seconds after its Turnstile verification. An agent that runs unattended therefore stops at every transfer until a person with a browser approves it.

### What pairing protects today

Pairing exists for one reason: a native client cannot run Turnstile, and creation requires a Turnstile-backed permit. Checked against each property it could plausibly carry:

| Property | Does pairing provide it? |
| --- | --- |
| Confidentiality of content, keys, or capabilities | No. The CLI generates `R`, `W`, `O`, `S`, `M`, and the second key locally. The permit is not bound to the transfer it funds. No adversary row in the threat model relies on pairing for secrecy. |
| Authentication of a person or machine | No. The service has no accounts. Approval proves that someone passed Turnstile and clicked approve, not who. |
| Attribution | No. Permits are unlinkable to people, and the service collects no identifiers by design. |
| Binding a request to its owner's key | No. The owner key never leaves the CLI, and pairing happens before the key exists. |
| Protection against phishing with write links | No. Anyone can create the same request form in a browser after one Turnstile solve. |
| Informed consent to a transfer | No. The pairing page shows no transfer details, only a code. |
| Short-lived CLI state | Yes, as a side effect. Stolen CLI state yields at most one permit that expires within 30 minutes. No long-lived bearer credential exists on the machine. |
| Abuse and cost control | **Yes.** It is the only per-creation control on the native route. One human Turnstile solve funds one resource, so the native route cannot bypass the gate that the web client passes. |

A person also notices each creation. This is not a control inside the [CLI boundary](../spec/cli-v1.md#security-boundary): a hostile agent is out of scope, and every transfer still reaches a person at hand-over, because the write link or recipient link has to be delivered to someone.

Without the permit, the remaining controls on creation are the [edge limiters](../spec/protocol-v1.md#authentication-backoff) and the policy limits: an envelope of at most 1,048,654 bytes kept for at most 30 days. The edge limiter allows 120 calls per minute per client network and route, and fails open. Send and request creation are separate routes, so one network may create 240 resources per minute. The service cannot inspect what it stores.

### State pairing creates

- Server: a pairing Durable Object per user code (poll-token tag, expiry, and after approval the request ID, issuance key ID, and permit expiry, kept until the permit expires), a request-ID Durable Object, and a permit Durable Object. The last two delete themselves when the permit window ends.
- CLI: a `pairing` phase in each operation record (poll token, user code), then the permit in the `creating` phase.
- Transcript: one pairing link and user code per operation.

## Decision drivers

1. After one setup step, an unattended agent creates transfers without a browser.
2. No change to confidentiality, protocol version 1 key schedules, bundles, envelopes, or test vectors. No change to the meaning of an existing route or stored record.
3. Abuse controls that are the only bound stay fail closed.
4. No accounts and no person identifier. A per-installation pseudonym is acceptable only with the person's explicit choice.
5. A person can revoke the authorization without access to the machine that holds it.

## Options

### A. Paired device grant

The person pairs once per machine and service origin. Approval creates a revocable **device grant** instead of a single permit. The CLI keeps a device token and uses it to mint a fresh single-use permit right before each creation. The token works like an OAuth refresh token and the permit like an access token: creation routes, permits, and resources stay exactly as they are.

#### Pairing

Device pairing uses new routes and new pages. The existing pairing routes, the `/pair` page, and their stored records stay byte-identical, and an old CLI keeps using them.

1. `kryptex` generates a random 16-byte device locator and a 32-byte device token, and calls `POST /api/v3/devices/pairings` with them and the requested maximum duration. The service returns a user code, as today.
2. The person opens `/pair/device`. The code is not prefilled: the person types the code their terminal shows. Turnstile runs in this document. The approve route verifies Turnstile, records the approval and a Turnstile-backed permit in the device-pairing object exactly as pairing does, and sets a claim cookie. It hands nothing out until the claim.
3. A full-page navigation opens a Turnstile-free confirmation page. This repeats the `/gate` to `/send` pattern: the device management capability is a protected asset, and Turnstile must not run in a document that holds one.
4. The confirmation page shows the duration the terminal asked for and offers **this transfer only** or **this machine until \<date\>**, with no preselection. It can shorten the duration but never extend it. For a device grant, the page generates a random 32-byte management token, sends it with the claim, and shows a **device management link** `/d#…` once, with the same copy and saved confirmation as other links. **This transfer only** mints one permit, as today's pairing does.
5. The CLI redeems with its device token and reports the grant's scope and expiry to the agent.

The claim cookie is single-use, HttpOnly, `Secure`, `SameSite=Strict`, scoped to the claim route, and lives no longer than the pairing. The threat model and product flows currently say that the permit cookie is the only state carried forward and that the pairing page sets no cookie. Both statements change.

#### Device object

- The device object initializes only if empty. It stores the device-token tag, the management-token tag, expiry, revoked state, and hourly creation counts for the last 24 hours. It never records which resources its permits created.
- A revoked or expired grant keeps a tombstone until its expiry, at most 90 days, so its locator cannot be re-initialized.
- The quota is enforced inside the device object and fails closed. Proposal: 50 creations per rolling 24 hours.

#### Minting

`POST /api/v3/devices/permits` (native only) takes the device locator, the device token, and a random request ID.

- The device object verifies the tag under the existing authorization lease and backoff. After `crypto.subtle.verify`, the charging transaction rechecks the generation, revoked state, and expiry before it counts the mint, as permit consumption does today.
- Each request ID is recorded until the grant expires. A known ID within the permit window replays the same permit without a charge, so a lost response is safe to retry. A known ID after the window is rejected. An unknown ID is charged. The exact mint time is kept only for the permit window; after that, only the spent ID remains.
- The Worker derives the permit seed with the existing issuance HMAC under a separate label, with the device locator and request ID as input. Device permits therefore never share a namespace with Turnstile request IDs. A device holder cannot reach another client's permit, and the permit object, which deletes itself after expiry, cannot be re-created from an old ID. This adds a label, not a construction.
- A device permit lives 120 seconds instead of 1,800. The CLI mints right before creation. After a revocation, outstanding permits stay valid for at most two minutes.

#### Status and revocation

`POST /api/v3/devices/status` and `POST /api/v3/devices/revoke` accept either the device token or the management token. Status returns state, expiry, remaining quota, and hourly counts. The `/d` page shows that status and offers revoke, following the shared fragment lifecycle. The device routes join the blinded-locator rate limiter as resource kind 5.

#### Expiry, scopes, and rotation

- The grant has a fixed expiry chosen at approval, at most 90 days. Minting a permit does not extend it. A sliding expiry would let a leaked token live as long as it is used.
- No scopes. Send and request creation have the same abuse and cost profile, so a scope that permits one and not the other bounds nothing. The quota and the expiry are the meaningful limits.
- No token rotation in the first version. The risk is accepted explicitly: a token copied from a backup or synced dotfiles mints permits up to the quota until revocation or expiry, and the hourly counts on the `/d` page are the detection. If that proves insufficient, rotation can be added without a new construction: the CLI sends a fresh next token with each mint, and the object accepts the old token until the new one is first used.

#### Threat-model impact

| Adversary | Outcome |
| --- | --- |
| Starts a device pairing and persuades someone to approve it as a device | Obtains a device grant: up to the quota per day until expiry or revocation, instead of one permit. This is the main regression. The person must type the code, pick the scope explicitly, and sees the duration in plain words. |
| Obtains a device token, for example from a backup or synced dotfiles | Mints permits up to the quota until expiry or revocation, plus outstanding permits for at most 120 seconds after revocation. Learns nothing about any transfer. The CLI state now holds a long-lived bearer credential, which it did not before. |
| Obtains a device management link | Sees the quota and hourly counts, and can revoke the grant, which only denies service to that machine. Cannot mint permits. |
| Reads an AI agent's transcript of CLI use | Sees a device pairing code once per machine and grant period instead of once per operation. Can approve that pairing first, up to the duration the CLI requested, and then hold the management link. The person's own approval then fails; the CLI reports the grant it received, and `kryptex device forget` followed by a new pairing replaces it. The grant still funds only the CLI that holds the device token. |
| Operates the service | Sees the device locator as a per-installation pseudonym, with the client network, on every mint. Can link creations made under one grant by timing. Learns no person identifier and no content. Hiding timing and IP addresses is already a non-goal. |

One Turnstile solve now funds up to quota × lifetime creations, for example 1,500 at 50 per day for 30 days, instead of one. The quota counts creations, not bytes: 50 a day of envelopes up to about 1 MiB kept up to 30 days is roughly 1.5 GB of live storage per grant. A byte quota would need permits bound to the transfer they fund, which is a protocol change. The edge limiter still applies to pairing and minting.

#### API and protocol changes

- New routes: device pairing start, approve, claim, and redeem; permit mint; status; revoke. A device Durable Object class and a device-pairing Durable Object class. Pages `/pair/device`, the confirmation page, and `/d`.
- Existing routes and stored records keep their meaning. A new CLI against an old service receives `400` from the device routes and falls back to the one-permit pairing.
- New server capability-tag values: resource kind `5=device`, capability kinds `5=device-mint` and `6=device-manage`. This follows the precedent of resource kind `4=pairing`: no existing value changes meaning. Both tokens are random 32-byte values and use the 30-second backoff cap of non-guessable capabilities.
- The device management link gets its own path and its own versioned fragment grammar in the API spec, not a new `KXB1` bundle kind, so protocol version 1 stays frozen.
- One new derivation label for device permit seeds. No new key schedule and no new construction.

#### CLI and migration

- A versioned device file per origin, `devices/<sha256(canonical origin)>.json` in the state directory, mode `0600`, under the existing directory ownership and permission checks. It holds the origin, locator, token, and expiry. It is never printed, and `list` does not show it.
- New operations with a valid device file mint a permit with a request ID recorded before the call, then continue to `creating` without a `pairing` phase. The first `create` then returns `hand_over_write_link` directly.
- `rate_limited`, network failures, and `5xx` from the mint route are retryable and keep the device file; concurrent mints from one machine meet the per-kind authorization lease and retry. Only the generic unavailable response means the grant is revoked or expired: the CLI deletes the device file and starts a pairing.
- In device mode, `creation_permit_required` from permit status or creation mints again with a fresh request ID instead of starting a pairing.
- Records already in the `pairing` phase finish through the one-permit flow. The record schema gains a minting phase, which an older CLI cannot parse; this is a local downgrade limit, not a protocol change.
- New commands: `kryptex device status` and `kryptex device forget` (revoke, then delete the file).
- The agent instructions change step 4: pairing happens once per machine, and the person picks a device grant when they want unattended use.

#### UX for an unattended agent

One approval per machine and grant period, which works from a phone. After that, creation needs no person. The only remaining human step is the hand-over that every transfer needs anyway. When the grant expires, the next `create` returns `action: pair`, as every `create` does today.

#### A-lite

A smaller variant omits the confirmation page, the claim cookie, and the management link. The scope choice moves into `/pair/device`, and revocation is only `kryptex device forget` plus expiry. It removes most of the web work, but a person who loses the machine cannot revoke the grant before it expires.

### B. No permit for native creation

Native creation requests carry no permit. The service relies on the edge limiters, size and lifetime limits, and the short link lifetimes that already exist. Turnstile stays on the web gate.

Threat-model impact:

- Confidentiality: unchanged.
- The pairing rows disappear from the threat model: no pairing codes in transcripts, no approval phishing, no long-lived credential in CLI state.
- The abuse assumption no longer holds. The native route bypasses the web gate entirely, so Turnstile protects nothing that a script cannot reach without it. One client network may create 240 resources per minute of up to about 1 MiB each, kept up to 30 days, and the limiter fails open. IPv6 clients are grouped by network prefix, and prefixes are cheap to rotate. A botnet multiplies all of this.
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

Rejected. It keeps permits unlinkable, which option A gives up, but every permit expires 1,800 seconds after the Turnstile solve, so it covers at most one 30-minute burst and not an unattended agent.

### F. Blind or anonymous tokens

The person passes Turnstile once and receives a batch of blindly signed tokens, as in Privacy Pass, that the service cannot link to the grant.

Rejected. It would restore unlinkability, but it requires a new cryptographic construction, which `AGENTS.md` forbids, and revocation of an unlinkable batch is impossible by design.

## Comparison

| | A. Device grant | B. No permit | Today |
| --- | --- | --- | --- |
| Human steps per transfer | Hand-over only | Hand-over only | Pairing and hand-over |
| Human steps per machine | One pairing per grant period | None | None |
| Creations per Turnstile solve | Up to quota × lifetime | Unbounded | 1 |
| Abuse bound | Fail-closed quota per grant, plus edge limiter | Edge limiter only, fails open | Turnstile per creation, plus edge limiter |
| Long-lived credential on the machine | Yes, revocable | No | No |
| Linkability of creations | Per grant, by timing | Per network only | Per network only |
| Revocation by a person | Management link, CLI, expiry | Not applicable | Not applicable |
| Protocol version 1 change | None | None | None |
| Server work | Two object classes, seven routes, three pages | Remove the permit check on native creation | None |

## Recommendation

**Option A, device grant.** Pairing buys no confidentiality, but it is the only thing that keeps the native route from being an anonymous, unbounded encrypted store with a public domain attached. Option A keeps one human Turnstile solve per machine and grant period, bounds abuse by a fail-closed quota, and gives the person a revocation handle, while removing the per-transfer prompt that blocks unattended agents. It costs a long-lived credential on the machine and a per-installation pseudonym at the service, both by the person's explicit choice.

Option B is acceptable only for a deployment whose operator accepts unbounded anonymous storage, for example a private instance behind an access proxy.

Choices for the owner:

1. Option A, A-lite, or B.
2. Grant lifetimes and the default. Proposal: 1, 7, 30, or 90 days; the CLI asks for 30 by default.
3. Quota. Proposal: 50 creations per rolling 24 hours per grant.
4. Whether to keep **this transfer only** on the confirmation page. Proposal: yes; it is today's flow.

## Consequences

If option A is chosen:

- The threat model, API spec, CLI spec, and product flows are updated before code. This includes the regressed row for an approved phishing pairing, the long-lived credential in CLI state, the device pseudonym in the storage section, and the claim cookie.
- The Worker gains two Durable Object classes and a migration tag. Old CLIs keep working unchanged.
- The abuse assumption changes from one Turnstile solve per creation to one Turnstile solve per grant, bounded by quota and lifetime.
