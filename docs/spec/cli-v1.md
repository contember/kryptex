# Kryptex CLI version 1

Status: draft specification for the first CLI release.

The CLI lets an AI coding agent obtain secrets from a person, or send secrets to a person, through a deployed Kryptex service without the secret values entering the agent's context. The agent runs shell commands. Anything a command prints becomes part of the agent's transcript, which may reach the model provider and its logs.

The CLI is a native Kryptex client. It uses protocol version 1 unchanged: the same key schedules, bundles, envelopes, payloads, and test vectors as the web client. It talks to the service through the native-client mode of the HTTP API and obtains creation permits through browser pairing; both are defined in the [HTTP API](api-v1.md).

## Security boundary

The CLI protects against **accidental** disclosure of secret values into the agent transcript. It does not protect against a hostile agent. An agent running as the same operating-system user can read the CLI state directory, the output file, and the process environment of commands it starts. Real isolation from the agent requires the person to run the CLI under an account, machine, or sandbox the agent cannot reach.

Within that boundary the CLI guarantees:

- Request answers, the pickup bundle, owner and decryption material, a send's second key, and its management link never appear on standard output or standard error.
- Every output is a fixed-shape JSON document built from an allowlist of fields. Errors are fixed codes with fixed messages. Exceptions, HTTP bodies, parsed state, payloads, and file contents are never printed.
- The service receives only what protocol version 1 permits: derived capabilities, encrypted envelopes, and policy metadata. Local target names, file paths, and commands never leave the machine.

What the agent does see, by design:

- A **write link** (`/r#…`). It lets its holder read the form and submit the one winning answer, but not read any answer. A party holding the transcript can submit unwanted data first. The CLI's request protection is link-only, as in the web default, because a second key would travel through the same transcript. A successful pickup does not authenticate the writer.
- A **recipient link** (`/s#…`) for a send. Sends always use the generated second key, and the second key is written only to a hand-off file for the person. The transcript alone cannot open the secret.
- A **pairing link and code**. They let their holder approve this one pairing, which grants a single creation permit to this CLI and nothing else.

## Installation and service origin

The CLI runs on Bun. Every command that creates an operation takes `--origin <url>`, or reads `KRYPTEX_ORIGIN` when the flag is absent. The origin must be an exact `https:` origin, or `http://localhost[:port]` for local development. The operation records it, and every later network call for that operation uses only the recorded origin.

## Commands

All commands except `skill` print exactly one JSON object followed by a newline on standard output and print nothing on standard error, except for redacted child output under `--exec`.

### `kryptex request create`

```text
kryptex request create --origin <url> --spec <form.json> [--ttl <seconds>]
  (--env-file <path> --env-dialect <expand|literal> | --exec -- <command> [args…])
```

Validates the form and the output target, writes the operation state, starts browser pairing, and returns immediately with the pairing action. It never blocks on a person.

The form spec is a JSON file:

```json
{"title":"Deploy credentials","fields":[{"target":"OPENAI_API_KEY","label":"OpenAI API key","help":"","type":"secret","required":true}]}
```

| Key | Rules |
| --- | --- |
| `title` | 1 through 120 UTF-8 bytes. |
| `fields` | 1 through 32 objects. |
| `target` | Required for every non-instruction field. Matches `[A-Za-z_][A-Za-z0-9_]*`, at most 128 bytes, unique in the spec. Absent for `instruction`. Stays local. |
| `label`, `help`, `type`, `required` | The protocol schema-field rules. `type` is `secret`, `text`, `long-secret`, `long-text`, or `instruction`. |

Additional keys are rejected. The CLI generates protocol field IDs `field001`, `field002`, … in spec order and stores the ID-to-target mapping locally; target names never become protocol IDs.

`--ttl` is one of the protocol TTL values and defaults to `604800`.

### `kryptex send create`

```text
kryptex send create --origin <url> --from-env-file <path> --env-dialect <expand|literal> --key <NAME> [--key <NAME> …]
  --handoff-file <path> [--ttl <seconds>] [--max-retrievals <1-10>]
```

Reads each named key from the source dotenv file and builds one send-fields payload with `label` equal to the key name and `type` equal to `secret`. A key matches `[A-Za-z_][A-Za-z0-9_]*` and is at most 120 bytes, the protocol label limit. A missing key, a duplicate `--key`, or an empty value fails before any network call. In the `expand` dialect, variables resolve only from the same file, never from the process environment. The values are encrypted under a fresh second key. `--ttl` defaults to `604800` and `--max-retrievals` to `1`.

The command writes the operation state, starts browser pairing, and returns immediately with the pairing action. The values are read and encrypted when the operation creates the send, not at this point, so the source file must still hold them then.

### `kryptex wait <handle> [--timeout <seconds>]`

Advances an operation until a person must act, the operation finishes, or the timeout elapses. The timeout defaults to `90` seconds so that a foreground call ends before common agent tool timeouts. It accepts 1 through 3600. `wait` takes no output flags: where results go is fixed when the operation is created.

### `kryptex list`

Prints metadata for every recorded operation: handle, kind, state, origin, expiry, and output target path or command name. It never prints capabilities or values. It is how an agent recovers a handle after a lost command output. A record that fails strict parsing is listed with state `invalid`.

### `kryptex discard <handle>`

Revokes the server resource when the operation still holds a management or owner capability and the resource is not terminal, then deletes the local state. A failed revoke is reported, and the local state is kept unless `--force` is given. `--force` also removes a record that fails strict parsing. A send gives up its management capability when it reaches `created`; from then on only the person holding the hand-off file can revoke it.

### `kryptex skill`

Prints the agent instructions in [CLI agent instructions](#agent-instructions).

## Output and exit codes

| Exit | Meaning |
| --- | --- |
| 0 | The operation finished: a request answer was delivered, or a send was created and its hand-off file was written. |
| 3 | A person must act. The output names the action and carries the link to hand over. |
| 4 | Still waiting. The timeout elapsed without a state change that needs the agent. Run `wait` again. |
| 1 | The operation failed. The output carries a fixed error code. Some failures are retryable with `wait`; the code says which. |
| 2 | Invalid command line or input. Nothing was recorded. |

Output shapes:

```json
{"action":"pair","handle":"k7f3q2m9xd","kind":"request","pairingExpiresAt":1787227800,"pairUrl":"https://host/pair#ABCD-EFGH","state":"pairing","userCode":"ABCD-EFGH"}
{"action":"hand_over_write_link","expiresAt":1787832000,"handle":"k7f3q2m9xd","kind":"request","state":"waiting","writeUrl":"https://host/r#…"}
{"expiresAt":1787832000,"handle":"k7f3q2m9xd","kind":"request","state":"waiting","writeUrl":"https://host/r#…"}
{"handle":"k7f3q2m9xd","kind":"request","state":"creating"}
{"delivered":{"keys":["OPENAI_API_KEY"],"path":".env"},"handle":"k7f3q2m9xd","kind":"request","receipt":"0A1B2C3D …","state":"delivered"}
{"delivered":{"command":"wrangler","exitCode":0,"keys":["OPENAI_API_KEY"]},"handle":"k7f3q2m9xd","kind":"request","receipt":"…","state":"delivered"}
{"action":"hand_over_recipient_link","expiresAt":1787832000,"handle":"p2c8…","handoffFile":"secrets/handoff.txt","kind":"send","recipientUrl":"https://host/s#…","state":"created"}
{"error":"pickup_lost","handle":"k7f3q2m9xd","message":"The answer was released by the service but not received. It cannot be recovered.","retryable":false}
{"operations":[{"expiresAt":1787832000,"handle":"k7f3q2m9xd","kind":"request","origin":"https://host","state":"waiting","target":".env"}]}
{"discarded":true,"handle":"k7f3q2m9xd","revoked":true}
{"error":"usage","message":"--spec is required."}
```

A pending pairing reports the same `pair` output with exit 4. A waiting request repeats `writeUrl` with exit 4, so an agent that lost the first output can still hand the link over. `expiresAt` in `list` is `null` until the resource exists.

`receipt` is the 64-digit display form of the `KXR1` receipt digest. Error codes are listed in [Errors](#errors).

## Operation state

### State store

The state directory is `$KRYPTEX_STATE_DIR`, else `$XDG_STATE_HOME/kryptex`, else `~/.local/state/kryptex`. The CLI creates it with mode `0700` and refuses to use it unless it is a directory owned by the current user with no group or other permission bits. Each operation is one file `<handle>.json` with mode `0600`, replaced atomically through an exclusive temporary file, `fsync`, and `rename`. A handle is 10 random lowercase Crockford Base32 characters and must match `[0-9a-hjkmnp-tv-z]{10}` before it is used in a path. A record that fails strict parsing is never acted on.

### Locks

Every command that changes an operation holds an exclusive lock on that handle for its whole run. Every write to an output file additionally holds a lock keyed by the SHA-256 of the canonical destination path. Locks are files created with `O_EXCL` that contain the holder's process ID; a lock whose process no longer exists is stale and may be taken over. A command that cannot take a lock fails with `busy` and changes nothing.

### Request lifecycle

```text
pairing → creating → waiting → picking → received → delivered
```

| State | Stored sensitive material | `wait` behaviour |
| --- | --- | --- |
| `pairing` | Poll token, user code. | Polls pairing redeem. On approval, stores the permit and moves to `creating`. An expired pairing starts a fresh one and returns the new pairing action. |
| `creating` | Permit, `R`, `W`, `O`, schema bytes, envelope, attempt ID, `settleNotAfter`, `clientNotAfter`. | Written before the create POST. On success, moves to `waiting`. After an ambiguous or interrupted create, reconciles through owner status exactly as product flows require; definitive absence discards the seeds and creates again with the same permit. A timeout during reconciliation keeps the attempt and exits 4 with state `creating`. A `creation_permit_required` response, from permit status or creation, starts a fresh pairing. |
| `waiting` | `R`, `W`, `O`, schema digest, `clientNotAfter`, `serverExpiresAt`, field mapping. | The first transition into `waiting` returns `hand_over_write_link` with exit 3. Later calls poll owner status with backoff from 2 to 15 seconds. `submitted` moves to `picking`. Terminal states end the operation. |
| `picking` | As `waiting`. | Written before the pickup POST. First preflights the output target. A lost pickup response queries owner status: `submitted` permits one more pickup, `picked_up` ends with `pickup_lost`. |
| `received` | `O`, `R`, exact `KXR1` bytes, schema digest, `clientNotAfter`, mapping. | Written after the full response is received and before decryption. Decrypts, verifies, and writes the output. An output failure keeps this state so that `wait` can retry after the cause is fixed. |
| `delivered` | None. | Completion record: handle, kind, target metadata, keys, and receipt. Repeated `wait` reprints the result. |

Before a completion record replaces a sensitive record, the output has been written and synced. An unavoidable window remains between the service committing `picked_up` and the CLI durably storing the `KXR1` bytes; a crash inside it loses the answer, and the CLI reports `pickup_lost`.

The CLI verifies a received answer against the locally stored request, not only against server behaviour. It requires the `KXR1` `clientNotAfter` and schema digest to equal the stored values, opens the envelope with the stored owner seed and locator, requires the embedded schema digest and public key to match, and maps answers by the stored protocol field IDs. Labels returned in the payload are never used for mapping.

### Send lifecycle

```text
pairing → creating → handoff → created
```

| State | Stored sensitive material | `wait` behaviour |
| --- | --- | --- |
| `pairing` | Poll token, user code. | As for requests. |
| `creating` | Permit, `S`, `M`, second key, envelope, attempt ID, `settleNotAfter`, `clientNotAfter`. | Written before the create POST. The source values are read and encrypted when entering this state and then exist only inside the envelope. Reconciliation uses send status with the management capability, as for requests. |
| `handoff` | `S`, `M`, second key, `serverExpiresAt`. | Writes the hand-off file, then moves to `created`. A write failure keeps this state for a retry. |
| `created` | Recipient link only. | Returns `hand_over_recipient_link` with exit 3 the first time and exit 0 after that. |

The hand-off file is created exclusively and must not already exist. It contains the second key, the management link, and fixed instructions: send the second key through a channel other than the recipient link, and keep the management link to check releases or revoke. The recipient link is reported only after the hand-off file is synced, so that the agent never hands over a link whose key does not exist anywhere.

## Output targets

### Path rules

`--env-file`, `--from-env-file`, and `--handoff-file` paths obey these rules, checked when the operation is created and again immediately before every read or write:

1. The current directory at creation must be inside a Git work tree. The CLI records the real path of its top level as the project root.
2. The path is resolved against the creation directory and must be inside the project root.
3. No component between the project root and the file may be a symbolic link. The file itself must be absent or a regular file.
4. Output paths (`--env-file`, `--handoff-file`) must be ignored by Git (`git check-ignore`) and not tracked (`git ls-files --error-unmatch` fails).

Output files are opened with `O_NOFOLLOW` and written through an exclusive temporary file in the same directory with mode `0600`, then synced and renamed. A temporary file can exist for the duration of one write and is removed on failure.

### Dotenv upsert

`--env-dialect` is required with `--env-file` and `--from-env-file`, because dotenv parsers disagree on `$` and backslashes:

| Dialect | Parsers | `$` |
| --- | --- | --- |
| `expand` | Bun, `dotenv` with `dotenv-expand` (Vite, Next.js) | Expanded unless written as `\$`. |
| `literal` | Node `--env-file`, `dotenv` | Never expanded; `\$` stays two characters. |

Encoding of one value, in order:

1. Reject a value containing NUL or CR.
2. In `expand`, reject a value containing `\$`, which has no unambiguous encoding, and a value ending in a backslash, which Bun reads as escaping the closing quote. Replace each `$` with `\$`, except a final `$`: Bun keeps `\$` literally before the closing quote, and a final `$` is never expanded.
3. If the value contains no `'`, write `'value'`.
4. Else, if it contains no backtick, write `` `value` ``.
5. Else, if it contains no `"` and no backslash and no line break, write `"value"`.
6. Else reject the value.

Line breaks are written raw inside the chosen quotes. Every accepted encoding has a round-trip test against the real parsers of its dialect.

Upsert rules for an existing file:

- An assignment line is `KEY=…` or `export KEY=…` with optional surrounding whitespace.
- A target that appears exactly once on a single-line assignment is replaced in place. A target that does not appear is appended at the end, after a newline if the file does not end with one.
- A target that appears more than once, or whose existing value spans several lines, fails with `env_file_conflict` before pickup. The CLI never prints the conflicting line.

An optional field left empty is not written, so an existing assignment stays. A value rejected by the encoder fails with `env_value_unrepresentable` and keeps the `received` state. The person can edit the file or the agent can discard the operation; the CLI does not change the target of a recorded operation.

### `--exec`

The command and its arguments are fixed at creation and recorded. After a verified pickup, the CLI runs the command once in the creation directory with the inherited environment plus one variable per answered target. Optional unanswered fields are set to the empty string. Standard input is closed.

The child's standard output and standard error are both forwarded to the CLI's standard error after redaction: every exact byte occurrence of each non-empty answer value is replaced with `[redacted:<TARGET>]`. Redaction is streamed with a carry buffer one byte shorter than the longest value, so occurrences split across reads are caught. It does not catch transformed values, such as encodings, substrings, or values split by the child itself; a command that prints transformed secrets will leak them.

A zero exit code completes the operation. A non-zero exit code or a failure to start reports `exec_failed` and keeps the `received` state. `wait` runs the command again, so commands should be idempotent.

## Network rules

- Requests go only to the recorded origin and only to the API routes of the operation.
- Redirects are rejected. TLS certificate verification is never disabled.
- Requests carry no `Origin`, no `Cookie`, and no Fetch Metadata headers. A creation permit is presented only in the `Kryptex-Create-Permit` header, and only on permit status and resource creation.
- Each request has a 30-second timeout. Response bodies are bounded: 64 KiB for JSON and the maximum envelope length plus 1 KiB for binary responses.
- The CLI never sends the owner seed, HPKE private key, second key, plaintext, field targets, or local paths.

## Errors

| Code | Retryable with `wait` | Meaning |
| --- | --- | --- |
| `busy` | yes | Another command holds the operation or destination lock. |
| `network` | yes | The service could not be reached, or the outcome of a non-consuming call is unknown. |
| `rate_limited` | yes | The service asked the client to slow down. |
| `unavailable` | no | The resource is missing, expired, revoked, or no longer accepts the operation. |
| `expired` | no | The resource reached its expiry before the operation finished. |
| `revoked` | no | The resource was revoked. |
| `pickup_lost` | no | The answer was released but not received. |
| `answer_invalid` | no | The received answer failed authentication or did not match the stored request. |
| `target_invalid` | yes | An output or input path no longer satisfies the path rules. |
| `env_file_conflict` | yes | The existing dotenv file cannot be updated safely. |
| `env_value_unrepresentable` | yes | A value has no encoding in the chosen dialect. |
| `source_invalid` | yes | A send source key is missing, empty, or the file cannot be parsed. |
| `exec_failed` | yes | The command failed to start or exited with a non-zero code. |
| `handoff_failed` | yes | The hand-off file could not be written. |
| `state_invalid` | no | The state record is missing or failed strict parsing. |
| `internal` | no | An unexpected failure. No detail is printed. |

## Agent instructions

`kryptex skill` prints these instructions verbatim. The repository also ships them as the agent skill `skills/kryptex/SKILL.md`, with the same text after its front matter:

```markdown
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
```
