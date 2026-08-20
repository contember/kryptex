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
    "PERMIT_ISSUANCE_KEY=\"$permit_issuance_key\"" \
    "RATE_LIMIT_KEY=\"$rate_limit_key\"" \
    > packages/worker/.dev.vars
)
```

The three random keys have different purposes and must not be reused. `CAPABILITY_HMAC_KEYRING` contains the `dev-v1` key selected by `CAPABILITY_ACTIVE_KEY_ID`.

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

## Browser flows

1. Open `/send` to create a recipient link and an optional independently delivered second key. Save the management link if later status, shorten, or revoke actions are required.
2. Open `/request` to define fields and create a write-only, write-once link. Save the pickup link; it cannot be recovered from the service.
3. Open a generated `/s#…`, `/m#…`, `/r#…`, or `/i#…` link in a fresh tab. The client copies the fragment into memory and immediately removes it from the address bar.
4. Use explicit retrieve, submit, or pickup actions. Page loads and `GET` requests are non-consuming.
5. In second-key mode, transfer the link and second key through independently secured channels. Two apps under one compromised device or account may not be independent.

Creation authorization opens `/gate` in an isolated tab. Complete Turnstile there, return to the original tab, and check authorization. The only intended cross-tab state is the HttpOnly permit cookie.

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

The repository intentionally has no deploy workflow and no production deploy script. Do not deploy manually. A future CI deployment must provide all of the following before its deploy step:

- a real Turnstile sitekey and secret for the production hostname, with the expected action `create_permit`;
- the exact production `EXPECTED_ORIGIN` and `TURNSTILE_EXPECTED_HOSTNAME`;
- independently generated production capability, permit-issuance, and rate-limit secrets;
- the private `kryptex-ciphertext` R2 bucket with public development URLs and custom domains disabled;
- the 14-day `v1/candidates/` lifecycle backstop; and
- a successful `bun run infra:predeploy:verify` CI gate.

The lifecycle apply order, privacy checks, and gate behavior are documented in [R2 candidate lifecycle backstop](./r2-lifecycle.md). Durable Object alarms delete active or terminal ciphertext earlier; the lifecycle rule only removes orphaned candidates.
