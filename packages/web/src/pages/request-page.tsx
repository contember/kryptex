import { useState } from "react";

import { usePreviewOperation } from "../preview-hooks";
import type { PreviewFieldType, PreviewRequestField } from "../preview-adapter";
import { reconcileCreation } from "../preview-transitions";
import { NavigationGuard, OperationNotice, PageIntro, PassphraseFields, PreviewMark, ProtectionOptions, ShareSlip, StatusMessage, VerificationStep, type OperationState, type Protection } from "../ui";
import type { ShareArtifact } from "../ui";
import { requiredArtifactsWording, requiredReceiptSaved, validatePassphrase } from "../validation";
import { openIsolatedVerification } from "../verification";

export function RequestPage({ initialGateOpened = false, initialPermit = false }: { readonly initialGateOpened?: boolean; readonly initialPermit?: boolean } = {}) {
  const operation = usePreviewOperation();
  const initial = operation.adapter.readRequestSchema();
  const [title, setTitle] = useState(initial.title);
  const [instructions, setInstructions] = useState(initial.instructions);
  const [fields, setFields] = useState<readonly PreviewRequestField[]>(initial.fields);
  const [nextId, setNextId] = useState(Math.max(...initial.fields.map((field) => field.id)) + 1);
  const [expiry, setExpiry] = useState("1 day");
  const [protection, setProtection] = useState<Protection>("second-key");
  const [passphrase, setPassphrase] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [gateOpened, setGateOpened] = useState(initialGateOpened);
  const [verified, setVerified] = useState(initialPermit);
  const [created, setCreated] = useState(false);
  const [creationAbsent, setCreationAbsent] = useState(false);
  const [state, setState] = useState<OperationState>("idle");
  const [saved, setSaved] = useState<Readonly<Record<string, boolean>>>({});
  const passphraseValidation = validatePassphrase(passphrase, confirmation);
  const protectionReady = protection !== "passphrase" || passphraseValidation.valid;
  const fieldsReady = fields.length > 0 && fields.every((field) => field.label.length > 0);
  const receiptSafe = requiredReceiptSaved(saved["link"] ?? false, protection, saved["factor"] ?? false, saved["pickup"] ?? false);

  function updateField(id: number, patch: Partial<Omit<PreviewRequestField, "id">>): void { setFields((current) => current.map((field) => field.id === id ? { ...field, ...patch } : field)); }
  function addField(): void { setFields((current) => [...current, { help: "", id: nextId, label: "Another secret", required: true, type: "secret" }]); setNextId((current) => current + 1); }
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
    operation.adapter.rememberRequestSchema({ fields, instructions, title });
    setState("working");
    try { await operation.run("create-request"); setCreated(true); setState("done"); }
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
    { channel: "Send this to the person responding.", id: "link", required: true, route: "/r", title: "Request link" },
    ...(protection === "second-key" ? [{ channel: "Send through a different secure channel.", id: "factor", required: true, title: "Second key" }] : []),
    { channel: "Keep this private to open the response.", id: "pickup", required: true, route: "/i", title: "Pickup link" }
  ];

  const requiredWording = requiredArtifactsWording(protection === "second-key" ? 3 : 2);
  if (created) return <div className="task-page"><NavigationGuard requiredWording={requiredWording} when={!receiptSafe} /><PageIntro title="Request created"><p>Send the request parts separately. Keep the pickup link private.</p></PageIntro><PreviewMark /><ShareSlip artifacts={artifacts} onSaved={(id, value) => { setSaved((current) => ({ ...current, [id]: value })); }} saved={saved} title={title} /><StatusMessage tone={receiptSafe ? "success" : "warning"}>{receiptSafe ? `${requiredWording} saved.` : `Save ${requiredWording} before leaving.`}</StatusMessage></div>;

  if (!verified) return <div className="task-page"><PageIntro title="Request secret"><p>They can send one encrypted response. The request link cannot read it back.</p></PageIntro><PreviewMark /><VerificationStep onAction={gateOpened ? () => { void check(); } : openGate} opened={gateOpened} state={state} /></div>;

  return <div className="task-page"><PageIntro title="Request secret"><p>They can send one encrypted response. The request link cannot read it back.</p></PageIntro><PreviewMark /><form className="simple-form" onSubmit={(event) => { event.preventDefault(); void create(); }}><label className="field-block"><span>Request title</span><input autoFocus onChange={(event) => { setTitle(event.currentTarget.value); }} placeholder="Production access handoff" value={title} /></label><label className="field-block"><span>Instructions <small>optional</small></span><textarea onChange={(event) => { setInstructions(event.currentTarget.value); }} placeholder="Anything they should know before responding" value={instructions} /></label><div className="request-items"><h2>What should they send?</h2>{fields.map((field, index) => <div className="request-item" key={field.id}><label><span>{index === 0 ? "Item" : `Item ${index + 1}`}</span><input onChange={(event) => { updateField(field.id, { label: event.currentTarget.value }); }} placeholder="API key" value={field.label} /></label><details><summary>More options</summary><div><fieldset className="compact-options"><legend>Answer format</legend>{(["secret", "short", "long"] satisfies readonly PreviewFieldType[]).map((type) => <label key={type}><input checked={field.type === type} name={`type-${field.id}`} onChange={() => { updateField(field.id, { type }); }} type="radio" /><span>{type === "secret" ? "Secret" : type === "short" ? "Plain" : "Multiline"}</span></label>)}</fieldset><label><span>Help text <small>optional</small></span><input onChange={(event) => { updateField(field.id, { help: event.currentTarget.value }); }} value={field.help} /></label><label className="check-label"><input checked={field.required} onChange={(event) => { updateField(field.id, { required: event.currentTarget.checked }); }} type="checkbox" /><span>Required</span></label>{fields.length > 1 ? <button className="text-button danger-text" onClick={() => { setFields((current) => current.filter((item) => item.id !== field.id)); }} type="button">Remove item</button> : null}</div></details></div>)}<button className="text-button" onClick={addField} type="button">Add another item</button></div><fieldset className="compact-options"><legend>Expires after</legend>{["1 hour", "8 hours", "1 day", "7 days"].map((value) => <label key={value}><input checked={expiry === value} name="expiry" onChange={() => { setExpiry(value); }} type="radio" /><span>{value}</span></label>)}</fieldset><details className="advanced"><summary>Advanced</summary><div><ProtectionOptions onChange={setProtection} value={protection} />{protection === "passphrase" ? <PassphraseFields confirmation={confirmation} message={passphraseValidation.message} onConfirmation={setConfirmation} onPassphrase={setPassphrase} passphrase={passphrase} valid={passphraseValidation.valid} /> : null}</div></details><p className="protection-summary"><span>Extra protection</span><strong>{protection === "second-key" ? "Separate second key" : protection === "passphrase" ? "Passphrase" : "Link only"}</strong></p><button className="primary-button full-button" disabled={title.length === 0 || !fieldsReady || !protectionReady || state === "working"} type="submit">{state === "working" ? "Creating…" : "Create request"}</button>{creationAbsent ? <StatusMessage tone="warning">No request was created. You can try again.</StatusMessage> : null}<OperationNotice retry={() => { void reconcile(); }} state={state} /></form></div>;
}
