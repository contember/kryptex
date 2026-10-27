# Kryptex HTTP API

Status: frozen resource boundary for version 1 with creation-permit version 2, native-client requests, and browser pairing.

## Encoding and common responses

Resource routes are `POST /api/v1/...`. Creation-permit routes are `POST /api/v2/create-permits...`. Request JSON uses `Content-Type: application/json` and UTF-8. Binary envelopes in JSON are canonical unpadded base64url. Locators decode to 16 bytes and tokens decode to 32 bytes.

Successful binary responses use `application/octet-stream`. All responses, including errors, set:

```text
Cache-Control: no-store
Referrer-Policy: no-referrer
X-Content-Type-Options: nosniff
Strict-Transport-Security: max-age=63072000; includeSubDomains
Kryptex-Server-Time: <integer Unix seconds at response creation>
```

Bearer-resource failures use one exact response regardless of missing state, wrong token, expiry, exhaustion, revocation, or invalid transition:

```http
HTTP/1.1 404 Not Found
Content-Type: application/json

{"error":"unavailable"}
```

Rate limiting returns `429` and `{"error":"rate_limited"}` before existence-dependent work. Malformed, oversized, or unsupported input returns `400` and `{"error":"invalid_request"}` before resource lookup. An invalid browser origin returns `403` and `{"error":"forbidden"}`. A missing, expired, or consumed create cookie returns `403` and `{"error":"creation_permit_required"}`. Unexpected failures return `500` and `{"error":"internal_error"}`. Raw exception text is never returned.

A request is a **browser request** when it carries an `Origin` header and a **native request** when it carries none of `Origin`, `Cookie`, and `Sec-Fetch-Site`. Any other combination is rejected with `403` and `{"error":"forbidden"}`.

A browser request must match the configured exact `Origin`; `Origin: null` never matches. Browser requests that mutate state must have `Sec-Fetch-Site: same-origin` when Fetch Metadata headers are present. A browser request carrying `Kryptex-Create-Permit` is rejected with `403` and `{"error":"forbidden"}`.

Native requests serve non-browser clients such as the [CLI](cli-v1.md). They carry no ambient credential: every capability is in the body, and a creation permit is presented only in the `Kryptex-Create-Permit` header. Because a native request can carry neither a cookie nor an origin a browser would attach, it cannot be used to spend a browser's permit cookie. Native requests are accepted on every route except `POST /api/v2/create-permits` and `POST /api/v2/create-permits/pairings/approve`, which only browsers may call.

API URLs with a query string are rejected before the body is read. The service does not enable credentialed cross-origin requests.

## Creation permit version 2

Version 2 moves verification before secret composition and extends the single-use permit lifetime without reinterpreting the retired `kx_create=v1...` cookie. Resource routes remain version 1.

### `POST /api/v2/create-permits`

Request:

```json
{"requestId":"550e8400-e29b-41d4-a716-446655440000","turnstileResponse":"..."}
```

`requestId` is a canonical lowercase UUID v4 and `turnstileResponse` is at most 2048 bytes. The Worker passes the request ID as Turnstile Siteverify `idempotency_key` so retries of the same verification use the same value. Verification must return `success=true`, the configured hostname, and action `create_permit`.

After verification, a Durable Object keyed by the request ID records the active permit-issuance key ID for the 1,800-second permit window. Retries reuse that recorded key ID across rolling key rotation. The Worker then decodes the UUID to 16 bytes and derives one stable pseudorandom permit seed with the selected versioned 32-byte secret:

```text
P = HMAC-SHA256(
  permitIssuanceKey,
  ASCII("kryptex/v1/create-permit/issuance") || 0x00 || requestId[16]
)
```

It then derives:

```text
permitPrk = Extract("kryptex/v1/create-permit/locator", P)
permitLocator = Expand(permitPrk, "kryptex/v1/create-permit/locator", 16)
permitToken = Expand(permitPrk, "kryptex/v1/create-permit/token", 32)
```

The request-ID Durable Object stores only the selected issuance key ID and its retention deadline, never the key or permit seed. The selected key must remain in the issuance keyring for at least 1,800 seconds after rotation. The Worker idempotently creates the permit Durable Object containing only the capability tag, key ID, creation time, expiry, and `unused` or `consumed` state. A retry with the same request ID derives the same `P` and returns the same unused permit; it never mints another permit from the same Turnstile solve. A consumed or expired permit requires a new Turnstile token and request ID. The Worker validates the Turnstile token within its 300-second validity window, then gives the Kryptex permit a maximum lifetime of 1,800 seconds. The response sets this cookie:

```text
Set-Cookie: kx_create_v2=v2.<base64url(P)>; Max-Age=1800; Path=/api/; Secure; HttpOnly; SameSite=Strict
```

Response:

```json
{"permitExpiresAt":1787229000,"serverTime":1787227200}
```

One permit authorizes one send or request creation. After body syntax, envelope, size, and policy validation, but before an R2 write, the create route snapshots the permit tag, key ID, and generation, awaits `crypto.subtle.verify`, then synchronously rechecks them and changes `unused` to `consumed`. WebCrypto never runs inside `transactionSync`. The route expires the cookie in its response. A storage or network failure after consumption requires a new permit.

Rejected Siteverify results return `403` and `{"error":"gate_failed"}`. A Siteverify timeout or upstream failure returns `503` and `{"error":"gate_unavailable"}`; retry uses the same request ID and token. Neither response includes upstream details.

### `POST /api/v2/create-permits/status`

Request body is `{}` and the permit cookie is ambient. The route snapshots the permit tag and generation, awaits `crypto.subtle.verify`, then synchronously rechecks and returns:

```json
{"permitExpiresAt":1787229000,"serverTime":1787227200,"state":"unused"}
```

Missing, expired, or consumed permits return `403` and `{"error":"creation_permit_required"}`. A crypto route checks this endpoint before rendering its form and again immediately before generating fresh seeds, nonce, padding, and `clientNotAfter`.

### Permit presentation

A browser presents the permit only through the `kx_create_v2` cookie. A native client presents it only through this request header on permit status, send creation, and request creation:

```text
Kryptex-Create-Permit: v2.<base64url(P)>
```

The value grammar, derivation, single use, and expiry are identical to the cookie. Creation routes never set or expire a cookie in response to a native request.

## Browser pairing for native clients

A native client cannot run Turnstile. Browser pairing lets a person pass Turnstile in a browser and hand the resulting single-use permit to one native client. One Turnstile solve still mints at most one permit. The flow follows the OAuth device authorization grant: a short user code that the person sees and approves, separated from a high-entropy poll token that only the native client holds.

### User code

A user code is 5 random bytes encoded as 8 Crockford Base32 characters with the second-key alphabet and input rules, displayed as two groups of four separated by a hyphen. It identifies a pairing and authorizes only its approval. The pairing Durable Object is named `pairing:` followed by the 8 canonical characters. Its capability-tag locator is the 5 code bytes followed by 11 zero bytes, with resource kind `4` and capability kind `4`.

### `POST /api/v2/create-permits/pairings`

Native requests only.

```json
{"pollToken":"<base64url-32>"}
```

The client generates the 32-byte poll token randomly and keeps it private. The Worker generates a user code and initializes the pairing Durable Object if it is empty, storing the poll-token capability tag, key ID, creation time, and expiry. It retries with a fresh code when the object already exists. A pairing expires 600 seconds after creation.

Response:

```json
{"pairingExpiresAt":1787227800,"serverTime":1787227200,"userCode":"ABCD-EFGH"}
```

### `POST /api/v2/create-permits/pairings/approve`

Browser requests only. The pairing page sends:

```json
{"requestId":"550e8400-e29b-41d4-a716-446655440000","turnstileResponse":"...","userCode":"ABCD-EFGH"}
```

The Worker verifies Turnstile exactly as permit issuance does, selects the issuance key through the request-ID Durable Object, derives `P`, and initializes the permit Durable Object. It sets no cookie. It then asks the pairing Durable Object to record the approval, storing only the request ID, issuance key ID, and permit expiry, never `P`. A pending, unexpired pairing records the approval. A pairing already approved with the same request ID repeats the success. Every other state returns the generic unavailable response. An approved pairing is retained until its permit expires so that redemption stays repeatable.

Response:

```json
{"state":"approved"}
```

Gate failures use the permit-issuance error codes.

### `POST /api/v2/create-permits/pairings/redeem`

Native requests only.

```json
{"pollToken":"<base64url-32>","userCode":"ABCD-EFGH"}
```

The pairing Durable Object verifies the poll-token tag under the per-resource authorization lease and backoff, with the 30-second cap of non-guessable capabilities. A pending pairing returns:

```json
{"pairingExpiresAt":1787227800,"state":"pending"}
```

An approved pairing returns the recorded request ID and key ID to the Worker, which derives `P` again from the issuance keyring and returns:

```json
{"permit":"v2.<base64url(P)>","permitExpiresAt":1787229000,"serverTime":1787227300,"state":"approved"}
```

Redemption does not consume the permit; repeating it after a lost response returns the same permit until the permit is consumed or expires. Missing, expired, and unauthorized pairings return the generic unavailable response.

### Phishing

Anyone can start a pairing and send its link to someone else. Approving it grants the starter one creation permit, which is worth one Turnstile solve. The pairing page therefore tells the person to approve only a code that their own terminal shows.

## Send routes

### `POST /api/v1/sends`

Requires an unused creation permit.

```json
{"attemptId":"<base64url-16>","clientNotAfter":1787230800,"envelope":"<base64url-KXE1>","locator":"<base64url-16>","manageToken":"<base64url-32>","maxRetrievals":1,"retrieveToken":"<base64url-32>","settleNotAfter":1787227290,"ttlSeconds":3600}
```

`attemptId` is random and immutable for this POST. At initial receipt, `settleNotAfter` must satisfy `serverNow + 15 <= settleNotAfter <= serverNow + 90`. The final Durable Object init rejects the attempt when its current server time is greater than `settleNotAfter`; no later retry may commit it. `ttlSeconds` is one of `900`, `3600`, `28800`, `86400`, `259200`, `604800`, `1209600`, or `2592000`. The clear `KXE1` header must have send mode and exactly match `clientNotAfter` and `maxRetrievals`. Creation follows the candidate-object sequence in the protocol using the supplied attempt ID.

Response:

```json
{"serverExpiresAt":1787230800}
```

### `POST /api/v1/sends/retrieve`

```json
{"locator":"<base64url-16>","retrieveToken":"<base64url-32>"}
```

Returns the exact stored `KXE1` bytes. Response metadata:

```text
Kryptex-Remaining-Releases: <decimal 0 through 9>
Kryptex-Server-Expires-At: <decimal Unix seconds>
```

These values describe the state committed for this release. This is the only recipient operation that consumes a release.

### `POST /api/v1/sends/status`

```json
{"locator":"<base64url-16>","manageToken":"<base64url-32>"}
```

Response while the authenticated state still exists:

```json
{"failedAccessAttempts":0,"releasedAt":[1787227200],"remainingRetrievals":1,"serverExpiresAt":1787230800,"state":"active"}
```

`releasedAt` holds one server timestamp per committed release, oldest first, and never more entries than the transfer's allowed opens. `failedAccessAttempts` counts presentations of a wrong retrieve token and saturates at 999. Neither field carries an address, a user agent, or any other recipient identifier; the service does not collect them.

Both success and generic unavailable include `Kryptex-State-Checked-At`, captured inside the locator Durable Object transaction at the authoritative state read. The Worker must not synthesize this header later.

`state` is `active`, `exhausted`, `revoked`, or `expired`. After expiry cleanup removes the tombstone, the route returns the generic unavailable response. The bundle timestamp is untrusted local data. If it has passed, the client may say that the link encodes a past timestamp, but it cannot claim server confirmation.

### `POST /api/v1/sends/revoke`

```json
{"locator":"<base64url-16>","manageToken":"<base64url-32>"}
```

Success returns `{"state":"revoked"}`.

### `POST /api/v1/sends/shorten`

```json
{"locator":"<base64url-16>","manageToken":"<base64url-32>","serverExpiresAt":1787229000}
```

The requested Unix-seconds value must be earlier than the stored expiry and later than server time. Success returns the stored `serverExpiresAt`. It also replaces the Durable Object alarm using milliseconds. The client rebuilds and offers a replacement management bundle containing the shortened timestamp; the old management capability still works but carries stale local metadata.

## Request routes

### `POST /api/v1/requests`

Requires an unused creation permit.

```json
{"attemptId":"<base64url-16>","clientNotAfter":1787230800,"envelope":"<base64url-KXE1>","locator":"<base64url-16>","ownerToken":"<base64url-32>","settleNotAfter":1787227290,"ttlSeconds":3600,"writeToken":"<base64url-32>"}
```

Attempt and settlement rules match send creation. The clear `KXE1` header must have request-schema mode, `maxRetrievals=0`, and a `clientNotAfter` matching the request. Creation uses a fresh schema candidate object and idempotent `init-if-empty`.

Response:

```json
{"serverExpiresAt":1787230800}
```

### `POST /api/v1/requests/schema`

```json
{"locator":"<base64url-16>","writeToken":"<base64url-32>"}
```

Returns the exact stored schema `KXE1` while state is `waiting`. It does not consume or mutate the request. The response includes `Kryptex-Server-Expires-At`.

### `POST /api/v1/requests/submit`

```json
{"envelope":"<base64url-KXR1>","locator":"<base64url-16>","writeToken":"<base64url-32>"}
```

The clear `KXR1` `schemaDigest` and `clientNotAfter` must match immutable request metadata. Candidate upload and the `waiting` to `submitted` CAS follow the protocol ordering.

Response:

```json
{"receipt":"<base64url-SHA-256-of-exact-KXR1>"}
```

The writer compares this value with the digest computed locally. A lost response has an unknown outcome: the response may have been accepted even though the client received no receipt.

### `POST /api/v1/requests/status`

```json
{"locator":"<base64url-16>","ownerToken":"<base64url-32>"}
```

Response while the tombstone exists:

```json
{"serverExpiresAt":1787230800,"state":"waiting"}
```

Both success and generic unavailable include `Kryptex-State-Checked-At` with the same Durable Object linearization semantics as send status.

`state` is `waiting`, `submitted`, `picked_up`, `revoked`, or `expired`. Status never returns schema or response bytes and never consumes pickup.

### `POST /api/v1/requests/pickup`

```json
{"locator":"<base64url-16>","ownerToken":"<base64url-32>"}
```

Returns the exact stored `KXR1` once and changes state to `picked_up`. Response metadata:

```text
Kryptex-Receipt: <base64url-SHA-256-of-exact-KXR1>
Kryptex-Server-Expires-At: <decimal Unix seconds>
```

The owner computes the digest over received bytes and treats the header only as a comparison aid.

### `POST /api/v1/requests/revoke`

```json
{"locator":"<base64url-16>","ownerToken":"<base64url-32>"}
```

Success returns `{"state":"revoked"}`.

### `POST /api/v1/requests/shorten`

```json
{"locator":"<base64url-16>","ownerToken":"<base64url-32>","serverExpiresAt":1787229000}
```

Rules match send shortening. Success returns the stored `serverExpiresAt`. The client rebuilds and offers a replacement pickup bundle containing the shortened timestamp; the old owner capability still works but carries stale local metadata.

## Logging and observability

Route-level telemetry may record route name, response class, duration bucket, and anonymous deployment identifiers. It must not record client IP beyond edge rate-limiter requirements, `Referer`, request bodies, cookies, fragments, locators, capabilities, envelope bytes, receipt digests, R2 keys, or decrypted values. Error reporting must use fixed error codes rather than serialized exceptions that may contain request data.
