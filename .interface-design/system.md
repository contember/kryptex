# Kryptex interface system

## Intent

The primary human is a developer or operator transferring a credential under mild time pressure. They must complete a short security ceremony without guessing what a control means. The interface should feel like a calm custody desk with tamper-evident paperwork, not a hacker terminal or consumer password manager.

## Domain vocabulary

Sealed envelope, split seal, retrieval ticket, custody receipt, burn mark, expiry clock, dead drop, pickup slip, and chain of custody.

## Signature

The transfer slip is the product-specific interaction pattern. It appears only after creation and groups the recipient link, optional second factor, channel instructions, and optional management link into one focused handoff artifact.

A small split-seal mark may connect the recipient link and second factor inside this slip. Do not repeat it throughout the application. It is drawn with CSS, not an image asset.

## Rejected defaults

- No dashboard sidebar or persistent lifecycle rail. Use one focused task per route.
- No neon-on-black security aesthetic. Use archival paper and graphite in light mode, muted ledger surfaces in dark mode.
- No grid of generic cards. Use sections that read as one custody document and detach only for capability receipts.
- No decorative shields or lock icons. Use the split seal, explicit labels, and state text.
- No rounded pill controls. Controls are compact, squared, and tactile.

## Palette

Light primitives:

```text
--ledger-canvas: #f4f0e7
--ledger-raised: #faf7f0
--ledger-inset: #ebe5da
--ink-primary: #1f2624
--ink-secondary: #4e5955
--ink-tertiary: #56615d
--ink-muted: #5e6864
--rule-soft: rgb(31 38 36 / 10%)
--rule-standard: rgb(31 38 36 / 18%)
--rule-emphasis: rgb(31 38 36 / 32%)
--control-border: #777f7b
--seal: #16745e
--seal-soft: #d9ebe5
--brass: #815217
--burn: #a23e32
--burn-soft: #f3ded9
```

Dark primitives:

```text
--ledger-canvas: #171b1a
--ledger-raised: #1e2422
--ledger-inset: #121615
--ink-primary: #ebe8df
--ink-secondary: #bcc2bd
--ink-tertiary: #a7afa9
--ink-muted: #959e98
--rule-soft: rgb(235 232 223 / 8%)
--rule-standard: rgb(235 232 223 / 15%)
--rule-emphasis: rgb(235 232 223 / 28%)
--control-border: #6f7974
--seal: #54aa91
--seal-soft: #203a33
--brass: #c39455
--burn: #d87568
--burn-soft: #432824
```

Color communicates action and state. Seal green means required factor input is present and well-formed; it does not claim server authorization. Brass means time or attention. Burn red is reserved for destructive or failed state. Status never relies on color alone. Muted colors remain text-safe at normal sizes; translucent rules and soft fills are decorative only.

## Depth and surfaces

Use borders and subtle surface shifts only. Do not use drop shadows. The page is `ledger-canvas`, capability receipts and overlays are `ledger-raised`, and inputs are `ledger-inset`. Quiet document rules use soft, standard, and emphasis tokens only as decoration. Every unfocused interactive control uses `control-border`, which has at least 3:1 contrast against adjacent permitted surfaces. Focus uses a 2px seal outline with a 2px canvas offset.

## Typography

- Prose and controls: self-hosted Atkinson Hyperlegible, weights 400 and 700.
- Capabilities, fingerprints, times, counters, and technical metadata: system `ui-monospace` with tabular numbers.
- Headings use weight and tracking, not oversized display typography.
- Secret values are monospace only when the content is already code-like; arbitrary prose remains in the primary typeface.

No remote fonts are permitted.

## Spacing and shape

- Base unit: 4px.
- Control gaps: 8px.
- Component padding: 12px or 16px.
- Section separation: 24px or 32px.
- Major flow separation: 48px.
- Radii: 4px controls, 8px sections, 12px dialogs only.
- Maximum reading width: 720px. Capability receipts may extend to 880px on wide screens.

## Navigation

The compact top line contains the wordmark, current task, and a quiet link to the security model. There is no account area, persistent route list, or lifecycle rail. The home page exposes only two primary actions: send a secret and request a secret. Security documentation is a quiet secondary link.

Each task route shows one form or one current state. Do not expose protocol stages, state simulators, or terminal-state menus in the primary interface.

## Components

- `TransferSlip`: the only prominent detached artifact; contains share values, short channel instructions, copy actions, and safe acknowledgement.
- `AdvancedDisclosure`: a native disclosure for protection mode, retrieval count, structured send fields, or uncommon field options. It starts closed.
- `RequestItem`: a label-first requested value. It defaults to required and secret; type, help, and optional state live under `More options`.
- `SecretField`: concealed/revealed text with explicit copy action.
- `PolicySummary`: plain-language TTL and retrieval contract.
- `BurnAction`: destructive control with typed confirmation for active resources.
- `StatusLine`: icon-free state marker using text, rule, and semantic color.

Every interactive component implements default, hover, active, focus-visible, disabled, loading, success, and error states where applicable.

Creation routes use progressive disclosure:

- send: secret, expiry, create; extra protection and retrieval count are advanced;
- request: title, plain instructions, one requested item, expiry, create; additional items and field options are secondary;
- request instructions are prose, never a visible field type;
- management and consumption routes show only the current status and one or two relevant actions.

Concealed values are absent from the accessibility tree until reveal. Dialogs move and contain focus, close on Escape when safe, and restore focus to their trigger. Requester-authored text is visually labeled **Provided by requester**.

## Motion

Use 120–180 ms opacity and transform transitions with deceleration. The split seal may align with a 160 ms translation when required factor input becomes well-formed. No bounce, spring, parallax, or ambient animation. Reduced-motion mode removes transforms.
