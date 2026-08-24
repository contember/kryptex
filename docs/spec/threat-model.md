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
6. Cloudflare Turnstile executes only in an isolated gate document with no fragment or secret fields. Full-page navigation unloads it before a crypto document opens. The only state carried forward is the HttpOnly permit cookie. Turnstile never executes in a document that holds plaintext or key material.

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

R2 stores encrypted envelopes only. Durable Objects store policy state, release timestamps, a wrong-token attempt count, random R2 object keys, and HMAC tags of capabilities. Release timestamps and the attempt count describe the transfer, not the person who opened it; no store holds a recipient address, user agent, or other identifier. The HMAC key is a Worker secret and is not stored with Durable Object state. No service-side store contains a content key, link seed, passphrase, random factor, or recipient private key.

## Active-client limitation

Content Security Policy, Trusted Types, dependency pinning, and a minimal bundle reduce accidental client compromise. They do not protect against an operator that intentionally serves malicious first-party JavaScript. The web client must not claim protection against this attack. A signed CLI or offline decryptor is a future mitigation and is outside the version 1 MVP.

## Abuse assumptions

The service cannot inspect encrypted content. Creation therefore requires a short-lived, single-use Turnstile-backed permit, strict size and lifetime limits, and approximate edge rate limiting by both client network plus route and blinded resource locator. External rate-limit bindings fail open because they are abuse and cost controls; the exact per-resource Durable Object authorization lease and backoff remain fail closed. The Worker validates Siteverify hostname and action. Retrieval and write routes must remain usable without Turnstile. Displayed content is plain text only; URLs are not made clickable.

Turnstile runs in an isolated top-level gate before the secret form opens. The gate does not read or write application data. After successful verification, a full-page navigation unloads Turnstile and intentionally carries forward only a versioned HttpOnly permit cookie. This gate is an abuse control, not part of encryption or capability authorization. A version 2 permit authorizes one creation attempt and expires within 30 minutes. If it expires while a draft is open, re-verification requires leaving that document; the client never persists the draft to bridge the navigation.
