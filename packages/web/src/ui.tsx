import { useEffect, useRef, useState } from "react";
import type { ReactNode, RefObject, SyntheticEvent } from "react";
import { useBlocker } from "react-router";

import { formatExactTime, formatTimeLeft } from "./format";
import type { FragmentCapture } from "./fragment";
import { isValidCrockfordFactor, normalizeCrockfordFactor, type PassphraseStrength } from "./validation";

export type Protection = "second-key" | "link-only" | "passphrase";
export type OperationState = "idle" | "working" | "waiting" | "unknown" | "unavailable" | "done";
export type Tone = "quiet" | "success" | "warning" | "danger";

export interface ShareArtifact {
  readonly channel: string;
  readonly id: string;
  readonly required: boolean;
  readonly title: string;
  readonly value: string;
}

export function useNowSeconds(): number {
  const [now, setNow] = useState(() => Math.floor(Date.now() / 1_000));
  useEffect(() => {
    const timer = window.setInterval(() => { setNow(Math.floor(Date.now() / 1_000)); }, 30_000);
    return () => { window.clearInterval(timer); };
  }, []);
  return now;
}

type CopyState = "idle" | "copied" | "manual";

function useCopy(): { readonly copy: (value: string) => void; readonly state: CopyState } {
  const [state, setState] = useState<CopyState>("idle");
  const timer = useRef<number | null>(null);
  useEffect(() => () => { if (timer.current !== null) window.clearTimeout(timer.current); }, []);
  function copy(value: string): void {
    function copied(): void {
      setState("copied");
      if (timer.current !== null) window.clearTimeout(timer.current);
      timer.current = window.setTimeout(() => { setState("idle"); }, 4_000);
    }
    try {
      void navigator.clipboard.writeText(value).then(copied).catch(() => { setState("manual"); });
    } catch {
      setState("manual");
    }
  }
  return { copy, state };
}

export function PageIntro({ title, step, children }: { readonly title: string; readonly step?: string; readonly children: ReactNode }) {
  return <header className="page-intro">
    {step === undefined ? null : <p className="eyebrow">{step}</p>}
    <h1>{title}</h1>
    <div>{children}</div>
  </header>;
}

export function InfoSection({ title, children }: { readonly title: string; readonly children: ReactNode }) {
  return <section className="info-section"><h2>{title}</h2>{children}</section>;
}

export function StatusMessage({ tone = "quiet", children }: { readonly tone?: Tone; readonly children: ReactNode }) {
  return <p className={`status-message status-message--${tone}`} role={tone === "danger" ? "alert" : "status"}>{children}</p>;
}

/** Quiet, non-alarming counterpart to StatusMessage: for counters and formatting help. */
export function FieldHint({ children }: { readonly children: ReactNode }) {
  return <span className="field-hint">{children}</span>;
}

export function AmbiguousNotice({ children }: { readonly children: ReactNode }) {
  return <div className="operation-notice"><strong>We could not confirm the result.</strong><div>{children}</div></div>;
}

export function ExpiryNote({ expiresAt, label = "Expires" }: { readonly expiresAt: number; readonly label?: string }) {
  const now = useNowSeconds();
  return <p className="expiry-note"><span>{label}</span><strong>{formatTimeLeft(expiresAt, now)}</strong><span className="mono">{formatExactTime(expiresAt)}</span></p>;
}

export function PolicySummary({ items, action }: { readonly items: readonly string[]; readonly action?: ReactNode }) {
  return <div className="policy-summary">
    <div><p className="eyebrow">This transfer</p><ul>{items.map((item) => <li key={item}>{item}</li>)}</ul></div>
    {action}
  </div>;
}

export function AdvancedDisclosure({ summary, children }: { readonly summary: string; readonly children: ReactNode }) {
  return <details className="advanced"><summary>{summary}</summary><div>{children}</div></details>;
}

export function StatusSheet({ rows }: { readonly rows: readonly { readonly label: string; readonly value: ReactNode }[] }) {
  return <dl className="status-sheet">{rows.map((row) => <div key={row.label}><dt>{row.label}</dt><dd>{row.value}</dd></div>)}</dl>;
}

export function ProtectionOptions({ value, onChange }: { readonly value: Protection; readonly onChange: (value: Protection) => void }) {
  return <fieldset className="option-list">
    <legend>Extra protection</legend>
    <label>
      <input checked={value === "second-key"} name="protection" onChange={() => { onChange("second-key"); }} type="radio" />
      <span>
        <strong>Separate second key</strong>
        <small>Recommended. Kryptex generates a short key. Send it through an independently secured channel, never with the link. Two apps on the same device or account may not be independent.</small>
      </span>
    </label>
    <label>
      <input checked={value === "passphrase"} name="protection" onChange={() => { onChange("passphrase"); }} type="radio" />
      <span>
        <strong>Passphrase</strong>
        <small>You choose a passphrase and tell the other person separately. Argon2id raises guessing cost but cannot make a weak passphrase safe.</small>
      </span>
    </label>
    <label>
      <input checked={value === "link-only"} name="protection" onChange={() => { onChange("link-only"); }} type="radio" />
      <span>
        <strong>Link only</strong>
        <small>Nothing else is needed to open it. The link is a bearer credential. Anyone who has it can try to open the content.</small>
      </span>
    </label>
  </fieldset>;
}

export function PassphraseFields({ passphrase, confirmation, onPassphrase, onConfirmation, message, strength, valid }: { readonly passphrase: string; readonly confirmation: string; readonly onPassphrase: (value: string) => void; readonly onConfirmation: (value: string) => void; readonly message: string; readonly strength: PassphraseStrength; readonly valid: boolean }) {
  const touched = passphrase.length > 0 || confirmation.length > 0;
  return <div className="passphrase-fields">
    <label>
      <span>Passphrase</span>
      <input autoComplete="off" onChange={(event) => { onPassphrase(event.currentTarget.value); }} spellCheck={false} type="password" value={passphrase} />
    </label>
    <label>
      <span>Repeat passphrase</span>
      <input autoComplete="off" onChange={(event) => { onConfirmation(event.currentTarget.value); }} spellCheck={false} type="password" value={confirmation} />
    </label>
    {!touched ? <FieldHint>At least 8 characters. The other person needs it to open the secret, so agree on a channel for telling them.</FieldHint>
      : valid && strength === "weak" ? <StatusMessage tone="warning">{message}</StatusMessage>
        : valid ? <StatusMessage tone="success">{message}</StatusMessage>
          : <FieldHint>{message}</FieldHint>}
  </div>;
}

/** Second keys are dictated and pasted between humans, so spacing must not decide whether they work. */
function compactFactor(value: string): string {
  return value.replaceAll(/\s+/gu, "");
}

export function normalizedFactorInput(mode: 0 | 1 | 2, value: string): string {
  if (mode !== 2) return value;
  const compact = compactFactor(value);
  return normalizeCrockfordFactor(compact) ?? compact;
}

/**
 * Recipient-side factor entry. The second key is dictated or pasted between humans,
 * so it forgives case, spacing, and the Crockford look-alikes before decoding.
 */
export function FactorInput({ mode, value, onChange }: { readonly mode: 1 | 2; readonly value: string; readonly onChange: (value: string) => void }) {
  if (mode === 1) {
    return <div className="field-block">
      <label><span>Passphrase</span><input autoComplete="off" onChange={(event) => { onChange(event.currentTarget.value); }} spellCheck={false} type="password" value={value} /></label>
      <FieldHint>The sender chose this passphrase and should have told you through a separate channel — not in the same message as the link.</FieldHint>
    </div>;
  }
  const compact = compactFactor(value);
  const recognized = compact.length > 0 && isValidCrockfordFactor(compact);
  return <div className="field-block">
    <label><span>Second key</span><input autoComplete="off" className="mono" onChange={(event) => { onChange(event.currentTarget.value); }} placeholder="XXXXX-XXXXX-XXXXX-XXXXX-XXXXXX" spellCheck={false} type="text" value={value} /></label>
    {compact.length === 0
      ? <FieldHint>Kryptex gave this key to the sender along with the link. They should have sent it to you a different way. Case, spacing, and dashes do not matter.</FieldHint>
      : recognized ? <span className="field-hint field-hint--good">The key has the expected shape. Opening it proves whether it is the right one.</span>
        : <FieldHint>Not a complete key yet — it is 26 characters, usually in five groups. Paste or type the whole thing.</FieldHint>}
  </div>;
}

function SplitSeal({ joined }: { readonly joined: boolean }) {
  return <span aria-hidden="true" className={joined ? "share-seal share-seal--joined" : "share-seal"}><span /><span /></span>;
}

function ShareRow({ artifact, saved, onSaved }: { readonly artifact: ShareArtifact; readonly saved: boolean; readonly onSaved: (value: boolean) => void }) {
  const clipboard = useCopy();
  return <li className={saved ? "share-row share-row--saved" : "share-row"}>
    <div className="share-row__head">
      <strong>{artifact.title}</strong>
      {artifact.required ? <span className="badge badge--required">Required</span> : <span className="badge">Optional</span>}
    </div>
    <p className="share-row__channel">{artifact.channel}</p>
    <div className="share-row__value">
      <code className="mono">{artifact.value}</code>
      <button className="secondary-button" onClick={() => { clipboard.copy(artifact.value); }} type="button">{clipboard.state === "copied" ? "Copied" : "Copy"}</button>
    </div>
    {clipboard.state === "manual"
      ? <label className="field-block manual-copy">
        <span>Copying was blocked — select and copy this manually</span>
        <input className="mono" onFocus={(event) => { event.currentTarget.select(); }} readOnly value={artifact.value} />
      </label>
      : null}
    <label className="check-label">
      <input checked={saved} onChange={(event) => { onSaved(event.currentTarget.checked); }} type="checkbox" />
      <span>{artifact.required ? "Saved" : "Saved or not needed"}</span>
    </label>
    <span aria-live="polite" className="sr-only">{clipboard.state === "copied" ? `${artifact.title} copied to clipboard.` : ""}</span>
  </li>;
}

export function ShareSlip({ title, note, artifacts, saved, onSaved, children }: { readonly title: string; readonly note?: ReactNode; readonly artifacts: readonly ShareArtifact[]; readonly saved: Readonly<Record<string, boolean>>; readonly onSaved: (id: string, value: boolean) => void; readonly children?: ReactNode }) {
  const stored = artifacts.filter((artifact) => saved[artifact.id] === true).length;
  const complete = stored === artifacts.length;
  return <section aria-labelledby="share-slip-title" className="share-slip">
    <header>
      <SplitSeal joined={complete} />
      <div>
        <p className="eyebrow">Ready to share</p>
        <h2 id="share-slip-title">{title}</h2>
      </div>
    </header>
    <div className="share-slip__lead">
      <p>Store every part before you leave. Kryptex keeps no copy of these, so this page cannot show them again.</p>
      {note}
    </div>
    <ol className="share-slip__rows">
      {artifacts.map((artifact) => <ShareRow artifact={artifact} key={artifact.id} onSaved={(value) => { onSaved(artifact.id, value); }} saved={saved[artifact.id] ?? false} />)}
    </ol>
    <footer className="share-slip__footer">
      <p className={complete ? "share-slip__progress share-slip__progress--complete" : "share-slip__progress"}>
        <span aria-live="polite">{stored} of {artifacts.length} parts stored</span>
      </p>
      {complete ? children : null}
    </footer>
  </section>;
}

export function SecretField({ label, value, codeLike = true }: { readonly label: string; readonly value: string; readonly codeLike?: boolean }) {
  const [revealed, setRevealed] = useState(false);
  const clipboard = useCopy();
  return <div className="secret-output">
    <div className="secret-output__head">
      <strong>{label}</strong>
      <div className="secret-output__actions">
        <button className="secondary-button" onClick={() => { setRevealed((current) => !current); }} type="button">{revealed ? "Hide" : "Reveal"}</button>
        {revealed ? <button className="secondary-button" onClick={() => { clipboard.copy(value); }} type="button">{clipboard.state === "copied" ? "Copied" : "Copy"}</button> : null}
      </div>
    </div>
    {revealed
      ? <>
        <output className={codeLike ? "mono" : undefined}>{value}</output>
        {clipboard.state === "manual"
          ? <label className="field-block manual-copy">
            <span>Copying was blocked — select and copy this manually</span>
            <input className={codeLike ? "mono" : undefined} onFocus={(event) => { event.currentTarget.select(); }} readOnly value={value} />
          </label>
          : null}
        <span aria-live="polite" className="sr-only">{clipboard.state === "copied" ? `${label} copied.` : clipboard.state === "manual" ? "Automatic copy failed." : ""}</span>
      </>
      : <span aria-hidden="true" className="concealed">•••• •••• ••••</span>}
  </div>;
}

export function FragmentNotice({ capture }: { readonly capture: FragmentCapture }) {
  return capture.hadFragment && capture.fragmentBytes !== null
    ? <p className="fragment-notice">The private part of this link was removed from the address bar and kept in memory only. Reopen the original link if you reload this page.</p>
    : <StatusMessage tone="warning">The private part of this link is missing. Open the original link again — copying only the visible address is not enough.</StatusMessage>;
}

export function OperationNotice({ state, retry }: { readonly state: OperationState; readonly retry?: () => void }) {
  if (state === "waiting") {
    return <div className="operation-notice">
      <strong>Nothing is ready yet.</strong>
      <p>Nobody has answered so far. Come back later and check again.</p>
      {retry === undefined ? null : <button className="secondary-button" onClick={retry} type="button">Check again</button>}
    </div>;
  }
  if (state === "unknown") {
    return <div className="operation-notice">
      <strong>We could not confirm the result.</strong>
      <p>The action may already have completed. Check the status before trying again — a retry can use up another open.</p>
      {retry === undefined ? null : <button className="secondary-button" onClick={retry} type="button">Check again</button>}
    </div>;
  }
  if (state === "unavailable") {
    return <div className="operation-notice">
      <strong>Unavailable.</strong>
      <p>The link may be expired, already used, revoked, or incomplete. Kryptex cannot tell you which — that is deliberate.</p>
    </div>;
  }
  return null;
}

export function ConfirmDialog({ open, title, description, confirmLabel, onCancel, onConfirm, restoreFocus }: { readonly open: boolean; readonly title: string; readonly description: string; readonly confirmLabel: string; readonly onCancel: () => void; readonly onConfirm: () => void; readonly restoreFocus: RefObject<HTMLButtonElement | null> }) {
  const dialogRef = useRef<HTMLDialogElement>(null);
  const [confirmation, setConfirmation] = useState("");
  useEffect(() => { const dialog = dialogRef.current; if (dialog === null) return; if (open && !dialog.open) dialog.showModal(); if (!open && dialog.open) dialog.close(); }, [open]);
  function close(): void { setConfirmation(""); onCancel(); window.setTimeout(() => restoreFocus.current?.focus(), 0); }
  function submit(event: SyntheticEvent<HTMLFormElement, SubmitEvent>): void {
    event.preventDefault();
    if (confirmation !== confirmLabel) return;
    setConfirmation("");
    onConfirm();
    dialogRef.current?.close();
    window.setTimeout(() => restoreFocus.current?.focus(), 0);
  }
  return <dialog className="confirm-dialog" onCancel={close} ref={dialogRef}>
    <form method="dialog" onSubmit={submit}>
      <h2>{title}</h2>
      <p>{description}</p>
      <label className="field-block">
        <span>Type <strong>{confirmLabel}</strong> to confirm</span>
        <input autoFocus className="mono" onChange={(event) => { setConfirmation(event.currentTarget.value); }} value={confirmation} />
      </label>
      <div>
        <button className="secondary-button" onClick={close} type="button">Cancel</button>
        <button className="danger-button" disabled={confirmation !== confirmLabel} type="submit">{confirmLabel}</button>
      </div>
    </form>
  </dialog>;
}

/** Destructive control with typed confirmation, per the interface system's burn action. */
export function BurnAction({ label, title, description, confirmLabel, onConfirm, disabled = false }: { readonly label: string; readonly title: string; readonly description: string; readonly confirmLabel: string; readonly onConfirm: () => void; readonly disabled?: boolean }) {
  const trigger = useRef<HTMLButtonElement>(null);
  const [open, setOpen] = useState(false);
  return <>
    <button className="danger-button" disabled={disabled} onClick={() => { setOpen(true); }} ref={trigger} type="button">{label}</button>
    <ConfirmDialog confirmLabel={confirmLabel} description={description} onCancel={() => { setOpen(false); }} onConfirm={() => { setOpen(false); onConfirm(); }} open={open} restoreFocus={trigger} title={title} />
  </>;
}

export function NavigationGuard({ when, requiredWording = "the required parts", title, description }: { readonly when: boolean; readonly requiredWording?: string; readonly title?: string; readonly description?: string }) {
  const blocker = useBlocker(when);
  const dialogRef = useRef<HTMLDialogElement>(null);
  useEffect(() => { function beforeUnload(event: BeforeUnloadEvent): void { if (when) event.preventDefault(); } window.addEventListener("beforeunload", beforeUnload); return () => { window.removeEventListener("beforeunload", beforeUnload); }; }, [when]);
  useEffect(() => { const dialog = dialogRef.current; if (dialog === null) return; if (blocker.state === "blocked" && !dialog.open) dialog.showModal(); if (blocker.state !== "blocked" && dialog.open) dialog.close(); }, [blocker.state]);
  if (blocker.state !== "blocked") return null;
  const reset = blocker.reset;
  function stay(): void { dialogRef.current?.close(); reset(); }
  return <dialog className="confirm-dialog" onCancel={(event) => { event.preventDefault(); stay(); }} ref={dialogRef}>
    <h2>{title ?? `Save ${requiredWording} first?`}</h2>
    <p>{description ?? "Kryptex keeps no copy of these links. Once this page closes, nothing can bring them back."}</p>
    <div>
      <button autoFocus className="primary-button" onClick={stay} type="button">Stay on this page</button>
      <button className="danger-button" onClick={() => { blocker.proceed(); }} type="button">Leave anyway</button>
    </div>
  </dialog>;
}
