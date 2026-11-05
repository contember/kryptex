# Threat model

Status: frozen for protocol version 1.

## Security objective

Kryptex transports short-lived secrets without exposing plaintext or decryption keys to the storage and API service. It minimizes the damage caused by a database leak, a leaked communication channel, link previews, and stale secret links.

## Protected assets

- Secret plaintext and structured form responses.
- Content encryption keys.
- Link seeds, secondary factors, and passphrases.
- Retrieval, write, owner, and management capabilities.
- Encrypted form schemas when labels or instructions are sensitive.

## Trust boundaries

1. The sender or form owner's browser creates keys and encrypts content.
2. The recipient or writer's browser derives capabilities and decrypts content.
3. The Worker receives ciphertext, high-entropy derived capabilities, policy metadata, and network metadata.
4. A per-resource Durable Object serializes state changes.
5. A private R2 bucket stores encrypted envelopes.
6. Cloudflare Turnstile executes only in an isolated gate document with no fragment or secret fields. Full-page navigation unloads it before a crypto document opens. The only state carried forward is an HttpOnly cookie: the permit cookie, or the device claim cookie that lets the confirmation page finish a device pairing. Turnstile never executes in a document that holds plaintext or key material.

7. A native client, such as the CLI, plays the browser's role on a user's machine. It creates keys, encrypts and decrypts content, and writes results to local files or a child process. It obtains a creation permit through browser pairing, in which a person passes Turnstile on a pairing page, or mints one with a device grant that such a pairing created.

## Adversaries and expected outcome

| Adversary | Expected outcome |
| --- | --- |
| Reads R2 and Durable Object storage | Learns ciphertext, sizes, timestamps, and policy metadata; cannot decrypt content. |
| Obtains a basic recipient link | Can retrieve and decrypt the secret. Basic links are bearer credentials. |
| Obtains a management link | Learns policy state, release timestamps, and the wrong-token attempt count for that transfer, and can revoke or shorten it. Cannot decrypt, and learns nothing identifying about the recipient. |
| Obtains only the link in split-key mode | Cannot authorize retrieval or decrypt content without the independent factor. |
| Obtains only the independent factor | Has no locator and cannot identify or decrypt a resource. |
| Obtains a passphrase-protected link | Can make online guesses serialized per resource with a backoff that reaches one hour, which bounds them to roughly 24 per day after warm-up. If the attacker also obtains ciphertext, or Durable Object tags plus the Worker HMAC key, it can test guesses offline. Argon2id raises cost but weak passphrases remain weak. |
| Runs a link preview crawler | Can load the generic application shell but cannot consume a capability through GET. |
| Sends concurrent retrievals | At most the configured number pass the Durable Object transaction. |
| Controls the intended recipient | Can save, copy, photograph, or forward plaintext after release. Expiry is not DRM. |
| Controls a sender or recipient device | Can read plaintext and keys used on that device. |
| Compromises only API or stored state while the reviewed client remains intact | Cannot decrypt ciphertext without separately captured link material or factors. |
| Actively changes the served web client | Can steal future plaintext or keys when a user loads the modified client. |
| Reads an AI agent's transcript of CLI use | Learns write links, recipient links, and pairing codes. Can submit the one answer to a link-only request first, or approve a pending pairing. Approving a device pairing first also gives it the management link of that grant: it sees mint counts and can revoke, but the grant still funds only the client holding the device token. Cannot read request answers, and cannot open a send without the second key in the hand-off file. |
| Starts a pairing and persuades someone to approve it | Obtains one creation permit, worth one Turnstile solve. If the person approves it as a device grant, obtains up to 50 permits per 24 hours until the grant expires, at most 90 days, or is revoked. Learns nothing about any transfer. |
| Obtains a device token, for example from a backup or synced configuration | Mints creation permits up to the grant's quota until it expires or is revoked, and keeps outstanding permits for at most 120 seconds after revocation. Learns nothing about any transfer. |
| Obtains a device management link | Sees the grant's expiry and hourly mint counts and can revoke it. Cannot mint permits. |
| Runs as the same OS user as the CLI, such as the agent itself | Can read the CLI state, output files, and child environments. The CLI does not defend this boundary. |
| Operates a malicious API behind an intact reviewed client | Can deny service, lie about state, retain or replay ciphertext, or release it too many times, but cannot decrypt without link material or a factor channel. A malicious web origin can instead change JavaScript and steal future data. Historical ciphertext remains protected only if the origin did not capture its link material or factors earlier. |

## Explicit non-goals

- Proving that a human saw, copied, or understood a secret.
- Revoking plaintext already revealed to an intended recipient.
- Defending a fully compromised endpoint.
- Protecting availability when an attacker can deny Cloudflare service.
- Cryptographically proving server-enforced retrieval counts against a malicious server.
- Guaranteeing immediate physical erasure from provider backups.
- Hiding connection timing, IP addresses, traffic volume, or coarse ciphertext size from Cloudflare.

## Storage compromise separation

R2 stores encrypted envelopes only. Durable Objects store policy state, release timestamps, a wrong-token attempt count, random R2 object keys, and HMAC tags of capabilities. Release timestamps and the attempt count describe the transfer, not the person who opened it; no store holds a recipient address, user agent, or other identifier. A device grant stores capability tags, its expiry, hourly mint counts, and spent request IDs. Its random device locator is a per-installation pseudonym that the person chose to create; it links the permits that grant minted, but no store records which resource a permit created. The HMAC key is a Worker secret and is not stored with Durable Object state. No service-side store contains a content key, link seed, passphrase, random factor, or recipient private key.

## Active-client limitation

Content Security Policy, Trusted Types, dependency pinning, and a minimal bundle reduce accidental client compromise. They do not protect against an operator that intentionally serves malicious first-party JavaScript. The web client must not claim protection against this attack. A signed CLI or offline decryptor is a future mitigation and is outside the version 1 MVP.

The Turnstile gate pages share the application's origin. A compromised Turnstile script cannot read a secret from the gate document, which holds none, and on `/pair/device` it cannot call the device claim routes. It could still open a same-origin page such as `/send` or `/pair/device/confirm` in a new window and script it, because same-origin windows can reach each other. Serving the gate pages from a separate origin would remove this; until then, Turnstile is trusted not to act against the page that embeds it.

## Abuse assumptions

The service cannot inspect encrypted content. Creation therefore requires a short-lived, single-use Turnstile-backed permit, strict size and lifetime limits, and approximate edge rate limiting by both client network plus route and blinded resource locator. External rate-limit bindings fail open because they are abuse and cost controls; the exact per-resource Durable Object authorization lease and backoff remain fail closed. A device grant replaces the per-creation Turnstile solve for one native client: its own creation required a Turnstile solve and a person's explicit choice, and it mints at most 50 permits per rolling 24 hours, enforced fail closed in its Durable Object, until it expires or is revoked. The Worker validates Siteverify hostname and action. Retrieval and write routes must remain usable without Turnstile. Displayed content is plain text only; URLs are not made clickable.

Turnstile runs in an isolated top-level gate before the secret form opens. The gate does not read or write application data. After successful verification, a full-page navigation unloads Turnstile and intentionally carries forward only a versioned HttpOnly cookie: the permit cookie after the gate, or the device claim cookie after a device pairing approval. This gate is an abuse control, not part of encryption or capability authorization. A version 2 permit authorizes one creation attempt and expires within 30 minutes. If it expires while a draft is open, re-verification requires leaving that document; the client never persists the draft to bridge the navigation.
