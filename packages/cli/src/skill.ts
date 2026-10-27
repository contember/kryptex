// Kept identical to "Agent instructions" in docs/spec/cli-v1.md; a test compares them.
export const AGENT_INSTRUCTIONS = `# Kryptex: getting secrets without seeing them

Use \`kryptex\` when you need a secret value from a person (an API key, a password, a token) or need to send one to a person. Secret values must never pass through your context.

Rules:
- Never print, cat, grep, echo, or otherwise read an output file, a hand-off file, or \`~/.local/state/kryptex\`. Refer to secrets only by path or variable name.
- Never put a secret value in a command line, a file you write yourself, or a message.
- Run \`kryptex wait <handle>\` in the foreground; repeat it while it exits with 4.

Ask a person for secrets:
1. Write a form spec with one field per secret. \`target\` is the environment variable name.
2. \`kryptex request create --origin <url> --spec form.json --env-file .env --env-dialect <expand|literal>\`.
   Use \`expand\` for Bun, Vite, Next.js; \`literal\` for Node \`--env-file\` or plain \`dotenv\`.
   Or deliver the values straight to a command: \`--exec -- <command> …\`; the values arrive as environment variables named by \`target\`.
3. Exit 3 with \`action: pair\`: ask the person to open \`pairUrl\` and approve \`userCode\`. Then run \`kryptex wait <handle>\`.
4. Exit 3 with \`action: hand_over_write_link\`: give \`writeUrl\` to the person who should fill in the form. Then run \`kryptex wait <handle>\` until exit 0.
5. Exit 0: the values are in the target. Tell the person which keys arrived. Do not read them.

Send secrets to a person:
1. \`kryptex send create --origin <url> --from-env-file .env --env-dialect <…> --key NAME --handoff-file <ignored path>\`.
2. Handle pairing as above.
3. Exit 3 with \`action: hand_over_recipient_link\`: give \`recipientUrl\` to the recipient. Tell the person that the second key and the management link are in \`handoffFile\` and that the second key must reach the recipient through a different channel. Do not read the file.

On exit 1, report the error code and message. \`kryptex list\` shows pending operations; \`kryptex discard <handle>\` revokes and removes one.
`;
