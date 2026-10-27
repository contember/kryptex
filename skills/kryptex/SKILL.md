---
name: kryptex
description: Get secrets (API keys, passwords, tokens) from a person, or send secrets to a person, without the values entering the agent's context, using the kryptex CLI. Use whenever a task needs a credential the agent does not have, instead of asking the user to paste it into the conversation, or when the user wants to hand a secret to someone securely.
---

# Kryptex: getting secrets without seeing them

Use `kryptex` when you need a secret value from a person (an API key, a password, a token) or need to send one to a person. Secret values must never pass through your context. Never ask a person to paste a secret into the conversation.

Rules:
- Never print, cat, grep, echo, or otherwise read an output file, a hand-off file, or `~/.local/state/kryptex`. Refer to secrets only by path or variable name.
- Never put a secret value in a command line, a file you write yourself, or a message.
- Pass `--origin https://kryptex.contember.com` unless `KRYPTEX_ORIGIN` is set or the person names another Kryptex service.
- `kryptex wait <handle>` returns within 90 seconds. Exit 4 means nothing changed yet: run it again, now or in a later session.

Ask a person for secrets:
1. Decide where the values must end up. The target is fixed at creation and cannot change later.
   - A dotenv file: `--env-file .env --env-dialect <expand|literal>`. The file must be ignored and untracked by Git. Use `expand` for Bun, Vite, Next.js; `literal` for Node `--env-file` or plain `dotenv`.
   - A command: `--exec -- <command> …`. The values arrive as environment variables named by `target`, standard input is closed, and output is redacted. For example `--exec -- sh -c 'printf %s "$API_KEY" | wrangler secret put API_KEY'`. A failed command runs again on the next `wait`, so make it idempotent.
2. Write a form spec with one field per secret, for example `{"title":"Deploy credentials","fields":[{"target":"API_KEY","label":"API key","help":"From the provider dashboard","type":"secret","required":true}]}`. `type` is `secret`, `text`, `long-secret`, `long-text`, or `instruction`; an instruction has no `target` and is not required. Every listed key is required and no other key is allowed.
3. `kryptex request create --spec form.json` plus the target options from step 1.
4. Exit 3 with `action: pair`: ask the person to open `pairUrl` and approve `userCode`. Then run `kryptex wait <handle>`.
5. Exit 3 with `action: hand_over_write_link`: give `writeUrl` to the person who should fill in the form. Anyone holding the link can submit the one accepted answer before `expiresAt`, so it must reach only that person.
6. Run `kryptex wait <handle>` until exit 0. If the form will be filled later, tell the person and stop; keep the handle, or find it again with `kryptex list`.
7. Exit 0: the values are in the target. Tell the person which keys arrived. Do not read them.

Send secrets to a person:
1. `kryptex send create --from-env-file .env --env-dialect <…> --key NAME --handoff-file <ignored path>`.
2. Handle pairing as above.
3. Exit 3 with `action: hand_over_recipient_link`: give `recipientUrl` to the recipient. Tell the person that the second key and the management link are in `handoffFile` and that the second key must reach the recipient through a different channel. Do not read the file.

On exit 1, report the error code and message; `retryable: true` means fix the cause and run `wait` again. Exit 2 means the command line was invalid and nothing was recorded. `kryptex list` shows operations; `kryptex discard <handle>` revokes and removes one.
