# Product flows

Status: frozen for the version 1 MVP.

## Shared language and claims

- Use **open** for the human action and **retrieval** or **release** for what the server counts. Never use **view**. Wherever a counter appears, adjacent copy states that it counts released copies, not people who read them.
- Use **second key** for a generated random factor.
- Use **passphrase** for a human-entered factor.
- Use **management link** for sender status and revocation.
- Use **pickup link** for the owner of a write-once request.
- Never use **zero knowledge**, **unbreakable**, **guaranteed deletion**, or **cannot be copied**.

The generated second key is the recommended protection. Its instruction says: **Send the second key through an independently secured channel. Two apps on the same compromised device or account may not be independent.** Link-only protection explicitly says that the link is a bearer credential. Passphrase protection says that weak passphrases can be guessed and that Argon2id raises cost but does not make a weak phrase safe.

## Shared fragment lifecycle

The `/s`, `/m`, `/r`, and `/i` shells all follow one rule. Before parsing or rendering secret-related UI, the shell copies the fragment into memory and synchronously removes it with `history.replaceState`. It never persists the copied bytes.

After removal, Reload, Back, crash recovery, and a duplicated scrubbed tab cannot reconstruct the capability. The page tells the user to reopen the original link. This applies to recipient, management, writer, and owner pages. No flow stores decrypted values or fragment material in `localStorage`, `sessionStorage`, IndexedDB, Cache Storage, or a service worker.

## Home

The home screen has two primary actions:

1. **Send a secret** — encrypt content and create a retrieval link.
2. **Request a secret** — define fields and create a write-once link.

It states that encryption and decryption happen in the browser and the service stores ciphertext. It links to the security model without marketing claims.

## Isolated creation authorization

The home actions perform a full-page navigation to `/gate` before opening a secret form. The gate contains Turnstile but no secret fields or fragment. After Siteverify succeeds, the Worker sets a single-use HttpOnly permit cookie and the browser performs another full-page navigation to `/send` or `/request`. The navigation unloads Turnstile before the crypto page opens. No third-party script executes in a document that holds plaintext or key material, and no secret material is placed in shared browser storage.

The crypto route checks the permit before rendering the form. Immediately before creation, it checks status again, uses the returned server time, and generates fresh seeds, nonce, padding, and `clientNotAfter`. If the permit expires while the form is open, the page keeps the draft in current-document memory and tells the user to copy it before a new full-page verification. It does not load Turnstile into the crypto document or persist the draft.

## Send creation

1. The user enters plain text or structured name/value fields.
2. The user selects lifetime and retrieval count.
3. Protection defaults to the recommended **Link + second key**. Alternatives are **Link only** and **Link + passphrase**.
4. A summary names each value and the channel through which it should travel.
5. After isolated creation authorization, the user confirms creation. Encryption happens locally with fresh material.
6. The receipt shows separate recipient-link, second-key when applicable, and management-link artifacts. Each has its own copy action; no action combines the link and second key.
7. The user confirms each required artifact separately: **Recipient link saved**, **Second key saved** when present, and **Management link saved or intentionally discarded**. A navigation warning is secondary only.

If the create response is lost, the page keeps the current seeds and encrypted bytes in memory and shows **Reconciling creation**. It polls send status with the in-memory management capability after 1, 2, 4, and then repeated 8-second delays until state appears or the status Durable Object reports `Kryptex-State-Checked-At` later than the request's server-enforced settlement deadline. Existing state returns `serverExpiresAt`, allowing exact receipt construction. Only unavailable linearized after that deadline is definitive; HTTP response time is not used. The client then obtains a new permit and generates fresh seeds, nonce, and envelope. The failed attempt may have left an unreachable encrypted R2 candidate until lifecycle cleanup. The client never blindly retries an ambiguous create POST.

## Send retrieval

1. Before release, the page shows only the timestamp encoded in the link and factor instructions. It does not query a non-consuming recipient status oracle.
2. Passphrase or second-key input occurs before the release action.
3. An explicit **Retrieve and consume one release** button performs the POST.
4. The app decrypts locally and renders text only.
5. Each value has an explicit copy control. Concealed values stay out of the visual and accessibility trees until intentional reveal.
6. The response shows the remaining releases committed with that response.
7. The page states that a recipient can retain plaintext and expiry cannot revoke already released content.

Wrong factors do not consume a release because the derived capability fails authorization. Errors do not reveal whether a resource is missing, expired, revoked, exhausted, or protected by another factor.

A lost response shows **Outcome unknown: a release may have been consumed**. There is no automatic retry. A manual retry requires a warning that it may consume an additional release if the first response was committed.

## Send management

While its authenticated state exists, the management screen shows active, exhausted, expired, or revoked state, expiry, remaining releases, revoke, and shorten. It never shows or reopens the secret. Delivery means ciphertext release, not successful decryption or human viewing.

After shortening, the page creates a replacement management link carrying the new timestamp and tells the user to replace the old local copy. After cleanup, generic unavailable is the only server statement. If the local bundle timestamp has passed, copy says: **This link says it has expired. The server record is unavailable, so the service could not confirm that state.**

After an ambiguous revoke or shorten response, the page refreshes authenticated status. It does not repeat a destructive operation automatically.

## Request creation

1. The owner defines 1 through 32 fixed field types: short text, secret text, multiline text, or a label-only instruction.
2. The owner selects lifetime and protection. The recommended default and alternatives match Send.
3. After isolated creation authorization, the owner confirms creation.
4. The receipt shows separate write-link, second-key when applicable, and pickup-link artifacts.
5. The owner confirms **Write link saved**, **Second key saved** when present, and **Pickup link saved** separately. The pickup link contains the only private-key seed and cannot be recovered.

An ambiguous create response enters the same **Reconciling creation** phase using request status and the in-memory owner capability. Existing state supplies `serverExpiresAt`. Only unavailable observed after the server-enforced settlement deadline permits a new permit and entirely fresh seeds, HPKE key pair, nonce, and envelope. An unreachable encrypted candidate may remain until lifecycle cleanup.

## Request writing

1. The writer supplies a factor when configured.
2. **Review requested fields** fetches and decrypts the schema without consuming the write.
3. Requester-authored title, labels, help, and instructions display **Provided by requester**.
4. The writer completes fixed safe controls. The final confirmation says that only one response can win and the link cannot be reused after acceptance.
5. The browser HPKE-encrypts one canonical response and computes its receipt fingerprint before upload.
6. After success, it compares the returned digest with the local digest and displays all digits.

If submit loses its response, the page retains the exact `KXR1` bytes and shows **Outcome unknown**. It never retries automatically. The user may explicitly retry the identical envelope: a first accepted write cannot be overwritten, while a previously uncommitted write may succeed. Generic unavailable after retry remains ambiguous to the writer.

A holder of the write capability can submit unwanted data first. Split-key or passphrase protection reduces this risk. The writer already knows the plaintext entered; write-only describes service access after submission.

## Request owner screen and pickup

The pickup link opens one owner screen:

- `waiting`: non-consuming status, expiry, shorten, and revoke;
- `submitted`: explicit **Retrieve response once**, expiry, shorten, and revoke;
- `picked_up`, `revoked`, or `expired`: terminal explanation without response data;
- generic unavailable: no claim beyond the missing server record.

Pickup releases the HPKE response once, derives the private key, decrypts locally, verifies the embedded schema digest and public key, and renders text-only fields with copy controls. After shortening, the screen offers a replacement pickup link containing the new local timestamp.

If pickup loses its response, the screen first queries owner status. It may retry only when state remains `submitted`. State `picked_up` means the response was released and cannot be recovered from the service. The UI states this before the user commits pickup.

The owner and writer compare all 64 hexadecimal fingerprint digits through a channel independent of the write link. A match means their browsers hold the same ciphertext bytes. It does not authenticate the writer, plaintext, or service behavior.

## Operation state contract

| Operation and trigger | User message | Retry rule | Capability effect | Safe next action and memory |
| --- | --- | --- | --- | --- |
| Any shell: malformed or unsupported bundle | This link is malformed or uses an unsupported version. | No API retry. | None. | Discard copied fragment bytes; request a new original link. |
| Create permit missing before form entry | Creation authorization is required. | Complete the isolated gate in the current tab. | No resource capability consumed. | Open the crypto form only after a full-page navigation unloads Turnstile. |
| Create permit expires while editing | Verification expired. | Copy the draft, then complete a new full-page gate. | No resource capability consumed. | Keep plaintext in current-document memory until the user leaves; do not persist it. |
| Create: local validation or encryption failure | Creation did not start. | Correct input or retry with fresh crypto material. | Permit is not consumed before valid request syntax. | Keep plaintext only while the page remains open. |
| Create: response lost after POST | Reconciling creation; outcome is not settled yet. | Poll manage/owner status with bounded backoff until state appears or settlement deadline passes; never repeat create. | Permit may be consumed and resource may still commit before the deadline. | Keep current seeds and envelope in memory until status or the deadline resolves it. |
| Retrieve: unavailable | This secret is unavailable. | No automatic retry. | Wrong authorization does not consume; real state is hidden. | Discard derived transient keys. |
| Retrieve: response lost | Outcome unknown; a release may be consumed. | Manual retry only after warning. | One release may have been consumed. | Keep fragment and factor in current-tab memory only. |
| Management or owner status: response lost | Status could not be confirmed. | Safe manual refresh. | Status is non-consuming. | Retain capability in current-tab memory. |
| Schema fetch: response lost or unavailable | Requested fields could not be loaded. | Manual retry is non-consuming while state remains waiting. | No write consumed. | Retain write capability in current-tab memory. |
| Submit: response lost | Outcome unknown; the response may be stored. | Explicit identical-envelope retry only. | The sole write may be consumed. | Retain exact encrypted response and local fingerprint, not a second variant. |
| Pickup: response lost | Outcome unknown; pickup may be consumed. | Query owner status; retry only if submitted. | Pickup may be consumed. | Retain owner capability; no plaintext is available after a lost picked-up response. |
| Revoke or shorten: response lost | Change not confirmed. | Refresh status; do not auto-repeat. | State may have changed. | Retain manage/owner capability. |
| Authenticated envelope past local bound | Content has expired locally. | Do not render or decrypt again. | A prior server release may already be consumed. | Discard plaintext and derived keys. |
| Authenticated decryption or schema validation fails | Content could not be authenticated. | No automatic retry of a consuming operation. | A release may already be consumed. | Discard partial plaintext and derived keys. |
| Exact backoff active | Too many attempts; wait before trying again. | Retry only after the shown generic delay. | No release or write consumed. | Keep factor input only in current-tab memory. |

No raw exception text reaches the user.

## Accessibility and clipboard safety

- Every operation is keyboard accessible and has visible focus. Status never relies on color alone.
- Secret inputs disable spellcheck and autocomplete where browsers honor it.
- Motion respects `prefers-reduced-motion`.
- Clipboard success and failure use an ARIA live region without announcing the copied secret.
- If Clipboard API access is denied or unavailable, the value remains in a selectable read-only control with manual-copy instructions.
- The app does not promise clipboard clearing or JavaScript memory erasure.
- `SplitSeal` is decorative and `aria-hidden`; adjacent text carries its meaning.
- `LifecycleRail` is an ordered list and marks the active stage with `aria-current="step"`.
- Dialogs move focus inside, contain focus, close on Escape when safe, and restore focus to their trigger.
