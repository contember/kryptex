import { useEffect, useRef, useState } from "react";
import type { ReactNode, RefObject, SyntheticEvent } from "react";
import { Link, useBlocker } from "react-router";

import type { FragmentCapture } from "./fragment";

export type Protection = "second-key" | "link-only" | "passphrase";
export type OperationState = "idle" | "working" | "waiting" | "unknown" | "unavailable" | "done";

export interface ShareArtifact {
  readonly channel: string;
  readonly id: string;
  readonly required: boolean;
  readonly route?: string;
  readonly title: string;
}

export function PageIntro({ title, children }: { readonly title: string; readonly children: ReactNode }) {
  return <header className="page-intro"><h1>{title}</h1><div>{children}</div></header>;
}

export function PreviewMark() {
  return <p className="preview-mark"><strong>UI preview.</strong> Crypto and API are not connected.</p>;
}

export function VerificationStep({ opened, state, onAction }: { readonly opened: boolean; readonly state: OperationState; readonly onAction: () => void }) {
  const label = opened ? "Check verification" : "Verify to continue";
  return <section className="verification-step" aria-labelledby="verification-title"><h2 id="verification-title">{label}</h2><p>{opened ? "Complete the check in the separate tab, then return here." : "The secret form stays closed until verification completes."}</p><button className="primary-button" disabled={state === "working"} onClick={onAction} type="button">{state === "working" ? "Checking…" : label}</button>{state === "waiting" ? <StatusMessage tone="warning">Verification is not ready yet.</StatusMessage> : <OperationNotice state={state} />}</section>;
}

export function InfoSection({ title, children }: { readonly title: string; readonly children: ReactNode }) {
  return <section className="info-section"><h2>{title}</h2>{children}</section>;
}

export function StatusMessage({ tone = "quiet", children }: { readonly tone?: "quiet" | "success" | "warning" | "danger"; readonly children: ReactNode }) {
  return <p className={`status-message status-message--${tone}`} role={tone === "danger" ? "alert" : "status"}>{children}</p>;
}

export function AmbiguousNotice({ children }: { readonly children: ReactNode }) {
  return <div className="operation-notice"><strong>We could not confirm the result.</strong><p>{children}</p></div>;
}

export function ProtectionOptions({ value, onChange }: { readonly value: Protection; readonly onChange: (value: Protection) => void }) {
  return <fieldset className="option-list"><legend>Extra protection</legend><label><input checked={value === "second-key"} name="protection" onChange={() => { onChange("second-key"); }} type="radio" /><span><strong>Separate second key</strong><small>Recommended. Send it through another secure channel.</small></span></label><label><input checked={value === "passphrase"} name="protection" onChange={() => { onChange("passphrase"); }} type="radio" /><span><strong>Passphrase</strong><small>A weak phrase can still be guessed.</small></span></label><label><input checked={value === "link-only"} name="protection" onChange={() => { onChange("link-only"); }} type="radio" /><span><strong>Link only</strong><small>Anyone with the link can try to open it.</small></span></label></fieldset>;
}

export function PassphraseFields({ passphrase, confirmation, onPassphrase, onConfirmation, message, valid }: { readonly passphrase: string; readonly confirmation: string; readonly onPassphrase: (value: string) => void; readonly onConfirmation: (value: string) => void; readonly message: string; readonly valid: boolean }) {
  return <div className="passphrase-fields"><label><span>Passphrase</span><input autoComplete="new-password" onChange={(event) => { onPassphrase(event.currentTarget.value); }} type="password" value={passphrase} /></label><label><span>Repeat passphrase</span><input autoComplete="new-password" onChange={(event) => { onConfirmation(event.currentTarget.value); }} type="password" value={confirmation} /></label><StatusMessage tone={valid ? "success" : "warning"}>{message}</StatusMessage></div>;
}

function SplitSeal() {
  return <span className="share-seal" aria-hidden="true"><span /><span /></span>;
}

export function ShareSlip({ title, artifacts, saved, onSaved }: { readonly title: string; readonly artifacts: readonly ShareArtifact[]; readonly saved: Readonly<Record<string, boolean>>; readonly onSaved: (id: string, value: boolean) => void }) {
  return <section className="share-slip" aria-labelledby="share-slip-title"><header><SplitSeal /><div><p>Ready to share</p><h2 id="share-slip-title">{title}</h2></div></header><div className="share-slip__rows">{artifacts.map((artifact) => <div className={artifact.required ? "share-row share-row--required" : "share-row"} key={artifact.id}><div><strong>{artifact.title}{artifact.required ? <span className="sr-only"> · Required</span> : null}</strong><p>{artifact.channel}</p></div><code>&lt;not generated in preview&gt;</code><div className="share-row__actions"><button disabled type="button">Copy unavailable</button>{artifact.route === undefined ? null : <Link to={artifact.route}>Open preview</Link>}</div><label><input checked={saved[artifact.id] ?? false} onChange={(event) => { onSaved(artifact.id, event.currentTarget.checked); }} type="checkbox" /><span>{artifact.required ? "Saved" : "Saved or not needed"}</span></label></div>)}</div></section>;
}

export function SecretField({ label, value, codeLike = true }: { readonly label: string; readonly value: string; readonly codeLike?: boolean }) {
  const [revealed, setRevealed] = useState(false);
  const [copyState, setCopyState] = useState<"idle" | "copied" | "manual">("idle");
  async function copy(): Promise<void> {
    try { await navigator.clipboard.writeText(value); setCopyState("copied"); }
    catch { setCopyState("manual"); }
  }
  return <div className="secret-output"><div><strong>{label}</strong><button onClick={() => { setRevealed((current) => !current); }} type="button">{revealed ? "Hide" : "Reveal"}</button></div>{revealed ? <><output className={codeLike ? "mono" : undefined}>{value}</output><button onClick={() => { void copy(); }} type="button">Copy</button>{copyState === "manual" ? <label><span>Copy manually</span><input onFocus={(event) => { event.currentTarget.select(); }} readOnly value={value} /></label> : null}<span className="sr-only" aria-live="polite">{copyState === "copied" ? `${label} copied.` : copyState === "manual" ? "Automatic copy failed." : ""}</span></> : <span className="concealed" aria-hidden="true">•••• •••• ••••</span>}</div>;
}

export function FragmentNotice({ capture }: { readonly capture: FragmentCapture }) {
  return capture.hadFragment && capture.fragmentBytes !== null ? <StatusMessage tone="success">Link opened. Its private part was removed from the address bar.</StatusMessage> : <StatusMessage tone="warning">This is a demo screen. Reopen the original link to use a real transfer.</StatusMessage>;
}

export function OperationNotice({ state, retry }: { readonly state: OperationState; readonly retry?: () => void }) {
  if (state === "waiting") return <div className="operation-notice"><strong>Nothing is ready yet.</strong><p>Wait and check again later.</p>{retry === undefined ? null : <button onClick={retry} type="button">Check again</button>}</div>;
  if (state === "unknown") return <div className="operation-notice"><strong>We could not confirm the result.</strong><p>The action may already have completed. Check status before trying again.</p>{retry === undefined ? null : <button onClick={retry} type="button">Check again</button>}</div>;
  if (state === "unavailable") return <div className="operation-notice"><strong>Unavailable.</strong><p>The link may be expired, used, revoked, or incorrect.</p></div>;
  return null;
}

export function ConfirmDialog({ open, title, description, confirmLabel, onCancel, onConfirm, restoreFocus }: { readonly open: boolean; readonly title: string; readonly description: string; readonly confirmLabel: string; readonly onCancel: () => void; readonly onConfirm: () => void; readonly restoreFocus: RefObject<HTMLButtonElement | null> }) {
  const dialogRef = useRef<HTMLDialogElement>(null);
  const [confirmation, setConfirmation] = useState("");
  useEffect(() => { const dialog = dialogRef.current; if (dialog === null) return; if (open && !dialog.open) dialog.showModal(); if (!open && dialog.open) dialog.close(); }, [open]);
  function close(): void { setConfirmation(""); onCancel(); window.setTimeout(() => restoreFocus.current?.focus(), 0); }
  function submit(event: SyntheticEvent<HTMLFormElement, SubmitEvent>): void { event.preventDefault(); if (confirmation !== confirmLabel) return; setConfirmation(""); onConfirm(); dialogRef.current?.close(); window.setTimeout(() => restoreFocus.current?.focus(), 0); }
  return <dialog className="confirm-dialog" onCancel={close} ref={dialogRef}><form method="dialog" onSubmit={submit}><h2>{title}</h2><p>{description}</p><label><span>Type <strong>{confirmLabel}</strong></span><input autoFocus onChange={(event) => { setConfirmation(event.currentTarget.value); }} value={confirmation} /></label><div><button onClick={close} type="button">Cancel</button><button className="danger-button" disabled={confirmation !== confirmLabel} type="submit">{confirmLabel}</button></div></form></dialog>;
}

export function NavigationGuard({ when, requiredWording = "the required parts" }: { readonly when: boolean; readonly requiredWording?: string }) {
  const blocker = useBlocker(when);
  const dialogRef = useRef<HTMLDialogElement>(null);
  useEffect(() => { function beforeUnload(event: BeforeUnloadEvent): void { if (when) event.preventDefault(); } window.addEventListener("beforeunload", beforeUnload); return () => { window.removeEventListener("beforeunload", beforeUnload); }; }, [when]);
  useEffect(() => { const dialog = dialogRef.current; if (dialog === null) return; if (blocker.state === "blocked" && !dialog.open) dialog.showModal(); if (blocker.state !== "blocked" && dialog.open) dialog.close(); }, [blocker.state]);
  if (blocker.state !== "blocked") return null;
  const reset = blocker.reset;
  function stay(): void { dialogRef.current?.close(); reset(); }
  return <dialog className="confirm-dialog" onCancel={(event) => { event.preventDefault(); stay(); }} ref={dialogRef}><h2>Save {requiredWording} first?</h2><p>Required links cannot be recovered after this page closes.</p><div><button autoFocus onClick={stay} type="button">Stay</button><button className="danger-button" onClick={() => { blocker.proceed(); }} type="button">Leave</button></div></dialog>;
}
