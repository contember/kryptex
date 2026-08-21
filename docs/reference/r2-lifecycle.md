# R2 candidate lifecycle backstop

The `kryptex-ciphertext` bucket is private. Its `v1/candidates/` prefix must have this lifecycle rule:

| Rule | Prefix | Expiration |
| --- | --- | --- |
| `kryptex-v1-candidate-backstop` | `v1/candidates/` | 31 days |

Committed ciphertext keeps the key it was uploaded under, so this prefix holds live objects as well as orphans. The expiration must therefore stay above the maximum supported lifetime of 30 days; 31 days is that maximum plus a one-day operational margin. Raising the maximum lifetime requires raising this rule in the same change.

The 31-day rule is only an orphan backstop. Durable Object alarms remain the primary cleanup path. They delete active or terminal ciphertext earlier when the protocol state releases, expires, revokes, or otherwise terminates a resource, and retry failed deletion work.

Cloudflare can expose an R2 bucket independently through an `r2.dev` URL or a custom domain, as described in [Public buckets](https://developers.cloudflare.com/r2/buckets/public-buckets/). Kryptex permits neither path. Ciphertext is available only through the Worker binding.

Cloudflare manages lifecycle rules as bucket-level configuration. The Worker `wrangler.jsonc` declares the bucket through an [R2 binding](https://developers.cloudflare.com/workers/wrangler/configuration/#r2-buckets), but the binding has no lifecycle-rule field. Cloudflare documents lifecycle configuration through the dashboard, Wrangler lifecycle commands, or the R2 API in [Object lifecycles](https://developers.cloudflare.com/r2/buckets/object-lifecycles/). The command syntax is documented in [Wrangler R2 commands](https://developers.cloudflare.com/workers/wrangler/commands/r2/).

## CI provisioning order

Run these steps after creating the bucket and before the first Worker deployment:

1. Apply the rule once:

   ```sh
   bun run infra:r2-lifecycle:apply
   ```

2. Run the predeploy gate. It prints the full Wrangler output and fails unless one lifecycle record contains the expected enabled rule, prefix, and 31-day expiration. It also fails unless the `r2.dev` URL is disabled and the bucket has no custom domains:

   ```sh
   bun run infra:predeploy:verify
   ```

3. Deploy the Worker through the normal CI deployment job only after verification passes.

The repository intentionally has no deployment workflow or deployment script yet. UI and API integration is incomplete, and the deployment architecture has not been authorized. Nothing can deploy through CI until a future workflow explicitly calls `infra:predeploy:verify` as a required gate before its deploy step.

The apply and verification commands use exactly `wrangler@4.124.0` and the bucket name already declared in `packages/worker/wrangler.jsonc`. Apply passes `--force` for noninteractive CI execution. CI authentication needs R2 Storage Write permission. Do not run the apply command as part of every deployment: `wrangler r2 bucket lifecycle add` appends a rule. For an existing bucket, verify first and reconcile a missing or mismatched rule deliberately so that unrelated bucket rules are not replaced.

Cloudflare notes that lifecycle deletion usually occurs within 24 hours after an object reaches its expiration threshold. The rule therefore must not be used for authorization, protocol expiry, or timely ciphertext deletion.
