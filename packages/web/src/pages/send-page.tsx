import { useState } from "react";

import { usePreviewOperation } from "../preview-hooks";
import { reconcileCreation } from "../preview-transitions";
import { NavigationGuard, OperationNotice, PageIntro, PassphraseFields, PreviewMark, ProtectionOptions, ShareSlip, StatusMessage, VerificationStep, type OperationState, type Protection } from "../ui";
import type { ShareArtifact } from "../ui";
import { requiredArtifactsWording, requiredReceiptSaved, validatePassphrase } from "../validation";
import { openIsolatedVerification } from "../verification";

interface SendField { readonly id: number; readonly label: string; readonly value: string; }

export function SendPage({ initialGateOpened = false, initialPermit = false }: { readonly initialGateOpened?: boolean; readonly initialPermit?: boolean } = {}) {
  const [text, setText] = useState("");
  const [structured, setStructured] = useState(false);
  const [advanced, setAdvanced] = useState(false);
  const [fields, setFields] = useState<readonly SendField[]>([{ id: 1, label: "API key", value: "" }]);
  const [nextId, setNextId] = useState(2);
  const [expiry, setExpiry] = useState("1 hour");
  const [retrievals, setRetrievals] = useState("1");
  const [protection, setProtection] = useState<Protection>("second-key");
  const [passphrase, setPassphrase] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [gateOpened, setGateOpened] = useState(initialGateOpened);
  const [verified, setVerified] = useState(initialPermit);
  const [created, setCreated] = useState(false);
  const [creationAbsent, setCreationAbsent] = useState(false);
  const [state, setState] = useState<OperationState>("idle");
  const [saved, setSaved] = useState<Readonly<Record<string, boolean>>>({});
  const operation = usePreviewOperation();
  const passphraseValidation = validatePassphrase(passphrase, confirmation);
  const hasSecret = structured ? fields.every((field) => field.label.length > 0 && field.value.length > 0) : text.length > 0;
  const protectionReady = protection !== "passphrase" || passphraseValidation.valid;
  const receiptSafe = requiredReceiptSaved(saved["link"] ?? false, protection, saved["factor"] ?? false);

  function updateField(id: number, key: "label" | "value", value: string): void { setFields((current) => current.map((field) => field.id === id ? { ...field, [key]: value } : field)); }
  function addField(): void { setFields((current) => [...current, { id: nextId, label: "Another secret", value: "" }]); setNextId((current) => current + 1); }
  function openGate(): void {
    openIsolatedVerification((url, target, features) => { window.open(url, target, features); });
    setGateOpened(true);
  }
  async function check(): Promise<void> {
    setState("working");
    try {
      const result = await operation.run("gate-status");
      if (result.outcome === "ready") { setVerified(true); setState("idle"); }
      else { setState("waiting"); }
    }
    catch { setState("unavailable"); }
  }
  async function create(): Promise<void> {
    setState("working");
    try { await operation.run("create-send"); setCreated(true); setState("done"); }
    catch { setState("unknown"); }
  }
  async function reconcile(): Promise<void> {
    setState("working");
    const result = await reconcileCreation(operation.adapter);
    if (result === "created") { setCreated(true); setState("done"); }
    else if (result === "absent") { setCreationAbsent(true); setState("idle"); }
    else { setState("unavailable"); }
  }

  const artifacts: readonly ShareArtifact[] = [
    { channel: "Send this to the recipient.", id: "link", required: true, route: "/s", title: "Secret link" },
    ...(protection === "second-key" ? [{ channel: "Send through a different secure channel.", id: "factor", required: true, title: "Second key" }] : []),
    { channel: "Optional. Keep it to revoke or shorten the link.", id: "manage", required: false, route: "/m", title: "Management link" }
  ];

  const requiredWording = requiredArtifactsWording(protection === "second-key" ? 2 : 1);
  if (created) return <div className="task-page"><NavigationGuard requiredWording={requiredWording} when={!receiptSafe} /><PageIntro title="Link created"><p>Share {requiredWording} separately.</p></PageIntro><PreviewMark /><ShareSlip artifacts={artifacts} onSaved={(id, value) => { setSaved((current) => ({ ...current, [id]: value })); }} saved={saved} title="Secret" /><StatusMessage tone={receiptSafe ? "success" : "warning"}>{receiptSafe ? `${requiredWording} saved.` : `Save ${requiredWording} before leaving.`}</StatusMessage></div>;

  if (!verified) return <div className="task-page"><PageIntro title="Send secret"><p>Create a temporary link that opens encrypted content.</p></PageIntro><PreviewMark /><VerificationStep onAction={gateOpened ? () => { void check(); } : openGate} opened={gateOpened} state={state} /></div>;

  return <div className="task-page"><PageIntro title="Send secret"><p>Create a temporary link that opens encrypted content.</p></PageIntro><PreviewMark /><form className="simple-form" onSubmit={(event) => { event.preventDefault(); void create(); }}><label className="field-block"><span>Secret</span>{structured ? <span className="field-hint">Structured fields are configured under Advanced.</span> : <textarea autoComplete="off" autoFocus onChange={(event) => { setText(event.currentTarget.value); }} placeholder="Paste a password, API key, or private note" spellCheck={false} value={text} />}</label><fieldset className="compact-options"><legend>Expires after</legend>{["15 minutes", "1 hour", "1 day", "7 days"].map((value) => <label key={value}><input checked={expiry === value} name="expiry" onChange={() => { setExpiry(value); }} type="radio" /><span>{value}</span></label>)}</fieldset><p className="protection-summary"><span>Extra protection</span><strong>{protection === "second-key" ? "Separate second key" : protection === "passphrase" ? "Passphrase" : "Link only"}</strong></p><details className="advanced" onToggle={(event) => { setAdvanced(event.currentTarget.open); }} open={advanced}><summary>Advanced</summary><div><ProtectionOptions onChange={setProtection} value={protection} />{protection === "passphrase" ? <PassphraseFields confirmation={confirmation} message={passphraseValidation.message} onConfirmation={setConfirmation} onPassphrase={setPassphrase} passphrase={passphrase} valid={passphraseValidation.valid} /> : null}<fieldset className="compact-options"><legend>Open up to</legend>{["1", "2", "5", "10"].map((value) => <label key={value}><input checked={retrievals === value} name="retrievals" onChange={() => { setRetrievals(value); }} type="radio" /><span>{value}×</span></label>)}</fieldset><button className="quiet-button" onClick={() => { setStructured((current) => !current); }} type="button">{structured ? "Use one text secret" : "Use structured fields"}</button>{structured ? <div className="inline-fields">{fields.map((field) => <div key={field.id}><label><span>Label</span><input onChange={(event) => { updateField(field.id, "label", event.currentTarget.value); }} value={field.label} /></label><label><span>Value</span><input autoComplete="off" onChange={(event) => { updateField(field.id, "value", event.currentTarget.value); }} spellCheck={false} type="password" value={field.value} /></label>{fields.length > 1 ? <button className="text-button danger-text" onClick={() => { setFields((current) => current.filter((item) => item.id !== field.id)); }} type="button">Remove</button> : null}</div>)}<button className="text-button" onClick={addField} type="button">Add field</button></div> : null}</div></details><button className="primary-button full-button" disabled={!hasSecret || !protectionReady || state === "working"} type="submit">{state === "working" ? "Creating…" : "Create link"}</button>{creationAbsent ? <StatusMessage tone="warning">No link was created. You can try again.</StatusMessage> : null}<OperationNotice retry={() => { void reconcile(); }} state={state} /></form></div>;
}
