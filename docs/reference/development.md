# Development and local operation

Kryptex is experimental and not production-ready. Use only synthetic test data. An independent cryptographic review and a tested production deployment are still required.

## Local setup

Install Bun 1.3.14 and OpenSSL. From the repository root, install the pinned workspace dependencies:

```sh
bun install --frozen-lockfile
```

Copy the public web environment example:

```sh
test ! -e packages/web/.env.local || {
  printf '%s\n' 'packages/web/.env.local already exists; preserve or remove it deliberately.' >&2
  exit 1
}
cp packages/web/.env.example packages/web/.env.local
```

It sets `VITE_TURNSTILE_SITE_KEY` to Cloudflare's always-pass test sitekey. The matching test secret belongs in `packages/worker/.dev.vars`. The following Bash snippet creates that file with three independent, canonical 32-byte base64url keys. It refuses to overwrite an existing file.

```bash
test ! -e packages/worker/.dev.vars || {
  printf '%s\n' 'packages/worker/.dev.vars already exists; preserve or remove it deliberately.' >&2
  exit 1
}

(
  umask 077
  capability_hmac_key="$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n')"
  permit_issuance_key="$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n')"
  rate_limit_key="$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n')"

  for key in "$capability_hmac_key" "$permit_issuance_key" "$rate_limit_key"; do
    [[ "$key" =~ ^[A-Za-z0-9_-]{43}$ ]] || exit 1
  done
  if [[ "$capability_hmac_key" == "$permit_issuance_key" ||
        "$capability_hmac_key" == "$rate_limit_key" ||
        "$permit_issuance_key" == "$rate_limit_key" ]]; then
    exit 1
  fi

  printf '%s\n' \
    'TURNSTILE_SECRET_KEY="1x0000000000000000000000000000000AA"' \
    "CAPABILITY_HMAC_KEYRING='{\"dev-v1\":\"$capability_hmac_key\"}'" \
    "PERMIT_ISSUANCE_KEYRING='{\"dev-v1\":\"$permit_issuance_key\"}'" \
    "RATE_LIMIT_KEY=\"$rate_limit_key\"" \
    > packages/worker/.dev.vars
)
```

The three random keys have different purposes and must not be reused. `CAPABILITY_HMAC_KEYRING` contains the `dev-v1` key selected by `CAPABILITY_ACTIVE_KEY_ID`. `PERMIT_ISSUANCE_KEYRING` contains the key selected by `PERMIT_ISSUANCE_ACTIVE_KEY_ID`.

During permit-issuance key rotation, add the new key and make it active in one deployment. Keep the previous key in the keyring for at least 30 minutes. The Worker records the selected key ID for each Turnstile request ID, so a retry remains mapped to the original permit during rolling deployment. Remove the previous key only after the overlap window.

Start the local Worker and Vite application:

```sh
bun run dev
```

Open exactly `http://localhost:5173`. The checked-in local Worker configuration expects:

| Setting | Local value |
| --- | --- |
| Browser origin | `http://localhost:5173` |
| Turnstile hostname | `localhost` |
| Turnstile action | `create_permit` |
| Turnstile sitekey | `1x00000000000000000000AA` |
| Turnstile secret | `1x0000000000000000000000000000000AA` |

These are Cloudflare's official always-pass dummy credentials. They are only for localhost. Never put either dummy value in production configuration. See [Cloudflare's Turnstile testing documentation](https://developers.cloudflare.com/turnstile/troubleshooting/testing/).

The local Worker treats this exact dummy credential pair as a deterministic development control. Only an exact `XXXX.DUMMY.TOKEN.XXXX` widget token is accepted, and only when both the configured browser-origin hostname and expected Turnstile hostname are `localhost`. That narrow mode does not call Siteverify because the local workerd outbound request is not reliable and the dummy response does not carry the production action. Any other secret or hostname uses normal Siteverify with the required hostname, action, and challenge timestamp checks. This local control is not production Turnstile validation.

## Browser flows

1. Open `/send` to create a recipient link and an optional independently delivered second key. Save the management link if later status, shorten, or revoke actions are required.
2. Open `/request` to define fields and create a write-only, write-once link. Save the pickup link; it cannot be recovered from the service.
3. Open a generated `/s#…`, `/m#…`, `/r#…`, or `/i#…` link in a fresh tab. The client copies the fragment into memory and immediately removes it from the address bar.
4. Use explicit retrieve, submit, or pickup actions. Page loads and `GET` requests are non-consuming.
5. In second-key mode, transfer the link and second key through independently secured channels. Two apps under one compromised device or account may not be independent.

The Send and Request actions navigate to `/gate` before opening a secret form. Complete Turnstile there. The browser then performs a full-page navigation to the selected form so the gate and its third-party script are unloaded. The only state carried to the form is the HttpOnly permit cookie.

## Repository gates

Run every root gate before proposing a change:

```sh
cpu-lease run -n 2 -- bun run check:vectors
cpu-lease run -n 2 -- bun run lint
cpu-lease run -n 2 -- bun run typecheck
cpu-lease run -n 2 -- bun run test
cpu-lease run -n 4 -- bun run build
```

`check:vectors` installs the separately pinned vector-tool dependencies before validating the frozen version 1 vectors. The Worker build is a Wrangler dry run; it does not deploy.

## Production prerequisites

Production deployment runs only through the repository's GitHub Actions workflow. Do not deploy manually. The protected `production` GitHub Environment must provide all of the following:

- a real Turnstile sitekey and secret for the production hostname, with the expected action `create_permit`;
- the exact production `EXPECTED_ORIGIN` and `TURNSTILE_EXPECTED_HOSTNAME`;
- independently generated production capability, permit-issuance, and rate-limit secrets;
- an issuance-key rotation policy that retains prior keys for at least 30 minutes;
- the private `kryptex-ciphertext` R2 bucket with public development URLs and custom domains disabled;
- the 31-day `v1/candidates/` lifecycle backstop; and
- Cloudflare account and API-token credentials; and
- a Worker URL or a separately configured Worker custom domain that exactly matches the expected origin.

The complete environment contract and pipeline behavior are documented in [Production deployment](./deployment.md). The lifecycle reconciliation and privacy checks are documented in [R2 candidate lifecycle backstop](./r2-lifecycle.md). Durable Object alarms delete active or terminal ciphertext earlier; the lifecycle rule only removes orphaned candidates.
