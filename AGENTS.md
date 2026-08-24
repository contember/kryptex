# Kryptex development rules

Kryptex is a capability-based, end-to-end encrypted secret transfer service.

## Security invariants

- Plaintext, link seeds, factors, passphrases, and content keys must never leave the browser.
- URL paths and queries must never contain share locators, capabilities, or key material.
- API routes must return `Cache-Control: no-store` and must not log request bodies, capabilities, or locators.
- A retrieval counter counts ciphertext releases, not human views.
- `GET` requests and page loads must never consume a retrieval or write capability.
- Server authorization must compare HMAC capability tags with `crypto.subtle.verify`.
- R2 buckets are private and must only be accessed through Worker bindings.
- Do not add analytics, third-party scripts, remote fonts, service workers, HTML rendering, Markdown rendering, or automatic URL linking to crypto pages.
- Do not implement new cryptographic constructions. Follow `docs/spec/protocol-v1.md` and its test vectors.
- A protocol change requires a new version. Never reinterpret an existing serialized value.

## Development

- Use Bun for package management and repository scripts.
- Keep TypeScript strict. Do not use `any`, type casts, `@ts-ignore`, or `@ts-expect-error`.
- Dependencies must be pinned to exact versions.
- Unit tests stay inside the package they exercise.
- Run full builds through `cpu-lease`.
- This is a public repository. Do not reference private projects, clients, URLs, or incidents.
