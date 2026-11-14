# Kryptex interface system

## Intent

The primary human is a developer or operator transferring a credential under mild time pressure. They must complete a short security ceremony without guessing what a control means. The interface should feel like a calm custody desk with tamper-evident paperwork, not a hacker terminal or consumer password manager.

## Domain vocabulary

Sealed envelope, split seal, retrieval ticket, custody receipt, burn mark, expiry clock, dead drop, pickup slip, and chain of custody.

## Signature

The transfer slip is the product-specific interaction pattern. It appears only after creation and groups the recipient link, optional second factor, channel instructions, and optional management link into one focused handoff artifact.

A small split-seal mark may connect the recipient link and second factor inside this slip. Do not repeat it throughout the application. It is drawn with CSS, not an image asset.

## Family

Kryptex is a sibling of the Fabrika console and wears its design language: IBM Plex, one brand blue, quiet tiles on a floor, status as a lamp, and category as a mono chip. Token values are the console's own, so the two products read as one family. Kryptex keeps its own wordmark and never draws Fabrika's mark.

## Rejected defaults

- No dashboard sidebar or persistent lifecycle rail. Use one focused task per route.
- No neon-on-black security aesthetic. Light mode is the console's pale floor with white controls; dark mode is its near-black floor with one-step-lighter tiles.
- No grid of generic cards. Use sections that read as one custody document and detach only for capability receipts.
- No decorative shields or lock icons. Use the split seal, explicit labels, and state text.
- No rounded pill controls. Controls are compact, squared, and tactile.
- No coloured side border on a rounded surface. Mark state with a lamp, a tint, or text colour.

## Palette

Light primitives:

```text
--floor: #f6f7f9
--recess: #f1f3f6
--tile: rgb(14 20 32 / 4.5%)
--plate-raised: #ffffff
--rule-soft / --rule / --rule-strong: rgb(14 20 32 / 5% / 10% / 18%)
--ink: #0e1117
--ink-2: #343d4a
--ink-3: #4b5563
--brand: #2544c2
--blueprint: #2544c2
--control: #ffffff
--control-rule: #7f8896
--lamp-ok: #177a4a
--lamp-run: #a8630a (text: #8a5409)
--lamp-stop: #bf2f2f
```

Dark primitives:

```text
--floor: #080a0d
--recess: #0a0d11
--tile: #15191f
--plate-raised: #1b2027
--rule-soft / --rule / --rule-strong: rgb(255 255 255 / 5.5% / 10% / 18%)
--ink: #f1f3f6
--ink-2: #b0b2b8
--ink-3: #85878e
--brand: #2544c2
--blueprint: #9dabe4
--control: #11151a
--control-rule: #666e7a
--lamp-ok: #3fc084
--lamp-run: #efa93f
--lamp-stop: #f4736f
```

The brand blue at full strength fills only the page's one constructive button and the wordmark in light mode. Links, the chosen option, and focus use the lighter blueprint mixes. Lamps are status only: green means a step is complete or a value is well-formed (it does not claim server authorization), amber means time or attention, red is reserved for destructive or failed state. Status never relies on colour alone. Washes and translucent rules are decorative only.

The theme follows the operating system through `prefers-color-scheme`.

## Depth and surfaces

Depth is quiet surface shifts, not borders or shadows. The page is `floor`; transfer slips, summaries, and revealed content are `tile`; inputs and share values are `control`. Hairline rules separate rows inside a tile. The confirmation dialog is the one surface that floats, and so the one with a shadow. Every unfocused interactive control uses `control-rule`, which keeps at least 3:1 contrast against adjacent surfaces; this is darker than the console's hairline on purpose. Focus is a 2px blueprint outline, or a blueprint border with a 3px soft ring on text fields.

## Typography

- Prose and controls: self-hosted IBM Plex Sans (variable, Latin subset).
- Capabilities, fingerprints, times, counters, chips, and technical metadata: self-hosted IBM Plex Mono with tabular numbers.
- Step labels and plate labels are small, letter-spaced capitals.
- Headings use weight and tight tracking, not oversized display typography.
- Secret values are monospace only when the content is already code-like; arbitrary prose remains in the primary typeface.
- Below 640px, body text is 15px and inputs use 16px so phones do not zoom into them; wider screens use the console's 14px.

No remote fonts are permitted.

## Spacing and shape

- Base unit: 4px.
- Control gaps: 8px.
- Component padding: 16px on phones, 24px inline on wider screens.
- Section separation: 24px or 32px.
- Major flow separation: 48px.
- Radii: 4px controls, 6px tiles, 10px dialogs only.
- Controls are 44px tall on phones and 36px from 640px up.
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
- `StatusLine`: icon-free state marker: a lamp (a dot with a soft halo) and words that say what it means.

Every interactive component implements default, hover, active, focus-visible, disabled, loading, success, and error states where applicable.

Creation routes use progressive disclosure:

- send: secret, expiry, create; extra protection and retrieval count are advanced;
- request: title, plain instructions, one requested item, expiry, create; additional items and field options are secondary;
- request instructions are prose, never a visible field type;
- management and consumption routes show only the current status and one or two relevant actions.

Concealed values are absent from the accessibility tree until reveal. Dialogs move and contain focus, close on Escape when safe, and restore focus to their trigger. Requester-authored text is visually labeled **Provided by requester**.

## Motion

Use 120–180 ms opacity and transform transitions with deceleration. The split seal may align with a 160 ms translation when required factor input becomes well-formed. No bounce, spring, parallax, or ambient animation. Reduced-motion mode removes transforms.
