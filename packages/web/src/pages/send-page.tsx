import { useState } from "react";
import type { SendField, SendPayload } from "@kryptex/contracts/payloads";
import type { TtlSeconds } from "@kryptex/contracts/protocol";
import type { SendCreateRequest } from "@kryptex/contracts/api";
import { deriveSendKeys, encodeBase64Url, encryptSendEnvelope, randomBytes } from "@kryptex/crypto";
import { ApiFailure } from "../api-client";
import { useClient } from "../client-context";
import { artifactUrl, createFactor, reconcileSendCreation, type FactorMaterial } from "../crypto-flow";
import { openIsolatedVerification } from "../verification";
import { NavigationGuard, OperationNotice, PageIntro, PassphraseFields, ProtectionOptions, ShareSlip, StatusMessage, type OperationState, type Protection, type ShareArtifact } from "../ui";
import { validatePassphrase, validateSendDraft } from "../validation";

interface PendingSend {
  readonly factor: FactorMaterial;
  readonly locator: Uint8Array<ArrayBuffer>;
  readonly manageSeed: Uint8Array<ArrayBuffer>;
  readonly request: SendCreateRequest;
  readonly sendSeed: Uint8Array<ArrayBuffer>;
}

export function SendPage() {
  const client = useClient();
  const [mode, setMode] = useState<"text" | "fields">("text");
  const [text, setText] = useState("");
  const [fields, setFields] = useState<readonly SendField[]>([{ concealed: true, label: "API key", value: "" }]);
  const [protection, setProtection] = useState<Protection>("second-key");
  const [passphrase, setPassphrase] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [ttl, setTtl] = useState<TtlSeconds>(3600);
  const [retrievals, setRetrievals] = useState(1);
  const [state, setState] = useState<OperationState>("idle");
  const [gateOpened, setGateOpened] = useState(false);
  const [artifacts, setArtifacts] = useState<readonly ShareArtifact[] | null>(null);
  const [pending, setPending] = useState<PendingSend | null>(null);
  const [reconciling, setReconciling] = useState(false);
  const [saved, setSaved] = useState<Readonly<Record<string, boolean>>>({});
  const phrase = validatePassphrase(passphrase, confirmation);

  function payload(): SendPayload {
    return mode === "text" ? { kind: "text", text } : { fields, kind: "fields" };
  }

  function updateField(index: number, key: "label" | "value", value: string): void {
    setFields(fields.map((field, fieldIndex) => fieldIndex === index ? { ...field, [key]: value } : field));
  }
  function selectTtl(value: number): void { if (value === 900 || value === 3600 || value === 28800 || value === 86400 || value === 259200 || value === 604800) setTtl(value); }

  function finishCreate(value: PendingSend, serverExpiresAt: number): void {
    const next: ShareArtifact[] = [{ channel: "Send this link to the recipient.", id: "recipient", required: true, title: "Recipient link", value: artifactUrl("/s", { factorMode: value.factor.mode, kind: 1, salt: value.factor.salt, sendSeed: value.sendSeed, serverExpiresAt }) }];
    if (value.factor.secondKey !== null) next.push({ channel: "Send through a different channel. Never append it to the link.", id: "factor", required: true, title: "Second key", value: value.factor.secondKey });
    next.push({ channel: "Keep this private if you want to manage the link.", id: "management", required: false, title: "Management link", value: artifactUrl("/m", { kind: 2, locator: value.locator, manageSeed: value.manageSeed, serverExpiresAt }) });
    setReconciling(false); setPending(null); setArtifacts(next); setState("done");
  }

  async function create(): Promise<void> {
    setState("working");
    if (pending !== null) {
      setReconciling(true);
      const reconciled = await reconcileSendCreation(client, pending.request.locator, pending.request.manageToken, pending.request.settleNotAfter);
      if (reconciled.kind === "created") finishCreate(pending, reconciled.serverExpiresAt);
      else { setReconciling(false); setPending(null); setState("unavailable"); }
      return;
    }
    let permit;
    try {
      permit = await client.permitStatus();
    } catch (error) {
      if (error instanceof ApiFailure && error.code === "creation_permit_required") {
        openIsolatedVerification((url, target, features) => window.open(url, target, features));
        setGateOpened(true);
        setState("waiting");
        return;
      }
      setState(error instanceof ApiFailure && error.ambiguous ? "unknown" : "unavailable");
      return;
    }
    try {
      const factor = await createFactor(protection, passphrase, confirmation);
      const sendSeed = randomBytes(32);
      const manageSeed = randomBytes(32);
      const keys = await deriveSendKeys(sendSeed, manageSeed, factor.mode, factor.factor);
      const clientNotAfter = permit.serverTime + ttl;
      const settleNotAfter = permit.serverTime + 60;
      const envelope = await encryptSendEnvelope({ clientNotAfter, contentKey: keys.contentKey, factorMode: factor.mode, maxRetrievals: retrievals, payload: payload() });
      const request = {
        attemptId: encodeBase64Url(randomBytes(16)), clientNotAfter, envelope: encodeBase64Url(envelope), locator: encodeBase64Url(keys.locator),
        manageToken: encodeBase64Url(keys.manageToken), maxRetrievals: retrievals, retrieveToken: encodeBase64Url(keys.retrieveToken), settleNotAfter, ttlSeconds: ttl
      };
      const attempt: PendingSend = { factor, locator: keys.locator, manageSeed, request, sendSeed };
      setPending(attempt);
      let serverExpiresAt: number;
      try {
        serverExpiresAt = (await client.createSend(request)).serverExpiresAt;
      } catch (error) {
        if (!(error instanceof ApiFailure) || !error.ambiguous) {
          setReconciling(false);
          setPending(null);
          if (error instanceof ApiFailure && error.code === "creation_permit_required") {
            openIsolatedVerification((url, target, features) => window.open(url, target, features));
            setGateOpened(true);
            setState("waiting");
            return;
          }
          throw error;
        }
        setReconciling(true);
        const reconciled = await reconcileSendCreation(client, request.locator, request.manageToken, settleNotAfter);
        if (reconciled.kind !== "created") { setReconciling(false); setPending(null); setState("unavailable"); return; }
        serverExpiresAt = reconciled.serverExpiresAt;
      }
      finishCreate(attempt, serverExpiresAt);
    } catch {
      setReconciling(false);
      setState("unavailable");
    }
  }

  const draft = validateSendDraft(mode, text, fields);
  if (artifacts !== null) {
    const complete = artifacts.every((artifact) => saved[artifact.id] === true);
    return <div className="task-page task-page--narrow"><PageIntro title="Share secret"><p>The encrypted transfer is ready.</p></PageIntro><ShareSlip artifacts={artifacts} onSaved={(id, value) => { setSaved({ ...saved, [id]: value }); }} saved={saved} title="Secret sealed" /><NavigationGuard when={!complete} /></div>;
  }
  return <div className="task-page task-page--narrow"><PageIntro title="Share secret"><p>Compose the secret first. Verification happens only when you seal it.</p></PageIntro>
    <fieldset className="compact-options"><legend>Content</legend><label><input checked={mode === "text"} name="content" onChange={() => { setMode("text"); }} type="radio" /><span>Text</span></label><label><input checked={mode === "fields"} name="content" onChange={() => { setMode("fields"); }} type="radio" /><span>Fields</span></label></fieldset>
    {mode === "text" ? <label><span>Secret</span><textarea autoComplete="off" onChange={(event) => { setText(event.currentTarget.value); }} rows={7} spellCheck={false} value={text} /></label> : <div className="inline-fields">{fields.map((field, index) => <div key={index}><label><span>Label</span><input onChange={(event) => { updateField(index, "label", event.currentTarget.value); }} value={field.label} /></label><label><span>Value</span><input autoComplete="off" onChange={(event) => { updateField(index, "value", event.currentTarget.value); }} spellCheck={false} type="password" value={field.value} /></label>{fields.length > 1 ? <button className="quiet-button" onClick={() => { setFields(fields.filter((_field, fieldIndex) => fieldIndex !== index)); }} type="button">Remove field</button> : null}</div>)}<button className="secondary-button" disabled={fields.length >= 32} onClick={() => { setFields([...fields, { concealed: true, label: "", value: "" }]); }} type="button">Add field</button></div>}
    <StatusMessage tone={draft.valid ? "success" : "warning"}>{draft.message}</StatusMessage>
    <ProtectionOptions onChange={setProtection} value={protection} />{protection === "passphrase" ? <PassphraseFields confirmation={confirmation} message={phrase.message} onConfirmation={setConfirmation} onPassphrase={setPassphrase} passphrase={passphrase} valid={phrase.valid} /> : null}
    <details className="advanced"><summary>Advanced</summary><div><label><span>Expires after</span><select onChange={(event) => { selectTtl(Number(event.currentTarget.value)); }} value={ttl}><option value={900}>15 minutes</option><option value={3600}>1 hour</option><option value={28800}>8 hours</option><option value={86400}>1 day</option><option value={259200}>3 days</option><option value={604800}>7 days</option></select></label><label><span>Maximum opens</span><input max={10} min={1} onChange={(event) => { setRetrievals(event.currentTarget.valueAsNumber); }} type="number" value={retrievals} /></label></div></details>
    <button className="primary-button full-button" disabled={!draft.valid || (protection === "passphrase" && !phrase.valid) || state === "working"} onClick={() => { void create(); }} type="button">{reconciling ? "Reconciling…" : state === "working" ? "Sealing…" : gateOpened ? "Check verification and seal" : "Seal and create link"}</button>
    {reconciling ? <StatusMessage tone="warning"><strong>Reconciling creation.</strong> Keep this tab open. The exact in-memory capability and encrypted attempt cannot be recovered if you leave.</StatusMessage> : state === "waiting" ? <StatusMessage tone="warning">Complete verification in the isolated tab, then press the button again. Your draft stays only in this tab.</StatusMessage> : <OperationNotice state={state} />}
    <NavigationGuard description="Leaving now permanently loses the in-memory capability needed to confirm this creation attempt." title="Keep confirming creation?" when={pending !== null} />
  </div>;
}
