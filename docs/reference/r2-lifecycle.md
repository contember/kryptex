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

The production workflow runs these steps before every Worker deployment:

1. Reconcile the bucket and managed lifecycle rule:

   ```sh
   bun run infra:r2:reconcile
   ```

   The command creates the bucket if it is absent. It reads the complete lifecycle configuration, preserves unrelated rules, replaces every stale copy of the managed rule with one exact rule, and verifies the result after the write.

2. Run the independent predeploy gate:

   ```sh
   bun run infra:predeploy:verify
   ```

   The gate fails unless exactly one managed rule is enabled with the expected prefix and 31-day expiration. It also fails unless the `r2.dev` URL is disabled and the bucket has no custom domains.

3. Deploy the Worker only after both commands pass.

Both commands use the authenticated Cloudflare API and the bucket name declared in `packages/worker/wrangler.jsonc`. They require `CLOUDFLARE_ACCOUNT_ID`, `CLOUDFLARE_API_TOKEN`, and R2 read/write permission. The reconciler sends one bucket-level lifecycle update only when the managed rule differs. It never appends duplicate rules.

Any other enabled delete rule whose prefix contains or is contained by `v1/candidates/` is a conflict. Reconciliation stops without writing. Public `r2.dev` access or an R2 custom domain also stops deployment; the command reports the drift but does not remove it automatically.

The complete CI setup is documented in [Production deployment](./deployment.md).

Cloudflare notes that lifecycle deletion usually occurs within 24 hours after an object reaches its expiration threshold. The rule therefore must not be used for authorization, protocol expiry, or timely ciphertext deletion.
