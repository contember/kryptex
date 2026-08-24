# Production deployment

The repository deploys through [`.github/workflows/deploy.yml`](../../.github/workflows/deploy.yml). Never run a production deploy from a workstation. A push to `main` or a manual workflow dispatch runs the same pipeline:

1. Run protocol-vector, lint, type, test, and build gates.
2. Enter the protected `production` GitHub Environment.
3. Validate all production variables and secrets.
4. Build the web assets with the production Turnstile sitekey.
5. Create the private R2 bucket if it is absent.
6. Reconcile and verify the candidate-object lifecycle rule and bucket privacy.
7. Deploy the Worker with Wrangler strict mode.
8. Run read-only and non-consuming HTTP smoke checks.

The pipeline does not perform an automatic rollback. A failed post-deploy smoke check leaves the new version visible and marks the workflow failed. Inspect the failure before rolling forward or using Cloudflare's version rollback controls.

## GitHub Environment

Create a GitHub Environment named `production`. Add approval rules before enabling the workflow for a public production service.

Configure these environment variables:

| Variable | Required value |
| --- | --- |
| `CLOUDFLARE_ACCOUNT_ID` | Account that owns the Worker and R2 bucket |
| `KRYPTEX_ORIGIN` | Exact HTTPS browser origin, without a path or trailing slash |
| `TURNSTILE_EXPECTED_HOSTNAME` | Hostname from `KRYPTEX_ORIGIN` |
| `VITE_TURNSTILE_SITE_KEY` | Real Turnstile sitekey for that hostname |
| `CAPABILITY_ACTIVE_KEY_ID` | Active ID present in `CAPABILITY_HMAC_KEYRING` |
| `PERMIT_ISSUANCE_ACTIVE_KEY_ID` | Active ID present in `PERMIT_ISSUANCE_KEYRING` |

Configure these environment secrets:

| Secret | Purpose |
| --- | --- |
| `CLOUDFLARE_API_TOKEN` | CI authentication |
| `CAPABILITY_HMAC_KEYRING` | JSON object of capability HMAC keys |
| `PERMIT_ISSUANCE_KEYRING` | JSON object of permit-issuance keys |
| `RATE_LIMIT_KEY` | Keyed locator-hash secret |
| `TURNSTILE_SECRET_KEY` | Real Turnstile secret |

The API token needs permission to deploy Workers and read and write R2 configuration in the selected account. Limit it to this account. Do not use a global API key.

The three cryptographic key purposes must use independent random 32-byte values encoded as canonical unpadded base64url. Keyring values are JSON objects. For example:

```json
{"v1":"REPLACE_WITH_A_43_CHARACTER_BASE64URL_VALUE"}
```

The validation gate rejects missing active keys, malformed keys, reused keys, HTTP origins, hostname mismatches, and Cloudflare's Turnstile dummy credentials. It does not print secret values.

During permit-issuance key rotation, add the new key and change `PERMIT_ISSUANCE_ACTIVE_KEY_ID` in the same deployment. Keep the previous key in the keyring for at least 30 minutes. Capability-key rotation must likewise retain every key ID needed by existing resources.

## Worker hostname

The workflow deploys the Worker and its assets. It does not create or change a Worker custom domain or DNS record. Before the first deploy, set `KRYPTEX_ORIGIN` to the account's Worker URL, or configure the intended Worker custom domain separately and then use that exact HTTPS origin. The Turnstile widget must allow the same hostname.

This boundary is deliberate. Pointing a production hostname at a Worker can replace existing traffic and needs an explicit DNS decision.

## Provisioning and drift behavior

The workflow owns these resources and values:

- Worker code, assets, bindings, variables, and required secrets declared by `packages/worker/wrangler.jsonc` plus the production command-line overrides;
- the `kryptex-ciphertext` R2 bucket when it is absent; and
- the exact `kryptex-v1-candidate-backstop` lifecycle rule.

The R2 reconciler preserves unrelated lifecycle rules. It refuses to deploy if another enabled delete rule overlaps `v1/candidates/`, if `r2.dev` access is enabled, or if the bucket has a custom domain. It does not silently remove public access or conflicting rules.

Wrangler runs with `--strict`. Conflicting remote Worker configuration therefore stops deployment instead of being overwritten silently. Secrets from the secrets file are additive; removing an obsolete secret requires a separate deliberate operation.

## Smoke checks

The post-deploy smoke command performs only these requests:

- `GET /` and verification of browser security headers;
- origin-less `GET /api/v1/probe`, which must return `403` and `Cache-Control: no-store`; and
- `OPTIONS /api/v1/probe` with the exact origin, which must return the expected CORS headers.

These requests do not include a capability, locator, key, or body. They cannot consume a retrieval or write capability.
