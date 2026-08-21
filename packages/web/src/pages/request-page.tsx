import { useState } from "react";
import type { RequestFieldType, RequestSchemaField, RequestSchemaPayload } from "@kryptex/contracts/payloads";
import type { TtlSeconds } from "@kryptex/contracts/protocol";
import type { RequestCreateRequest } from "@kryptex/contracts/api";
import { deriveHpkeKeyPair, deriveRequestOwnerKeys, deriveRequestWriteKeys, encodeBase64Url, encryptRequestSchemaEnvelope, randomBytes } from "@kryptex/crypto";
import { ApiFailure } from "../api-client";
import { useClient } from "../client-context";
import { artifactUrl, createFactor, reconcileRequestCreation, requestFieldId, type FactorMaterial } from "../crypto-flow";
import { NavigationGuard, OperationNotice, PageIntro, PassphraseFields, ProtectionOptions, ShareSlip, StatusMessage, type OperationState, type Protection, type ShareArtifact } from "../ui";
import { validatePassphrase, validateRequestDraft } from "../validation";
import { gatePath } from "../verification";

interface DraftField { readonly help: string; readonly label: string; readonly required: boolean; readonly type: RequestFieldType; }
interface PendingRequest { readonly factor: FactorMaterial; readonly locator: Uint8Array<ArrayBuffer>; readonly ownerSeed: Uint8Array<ArrayBuffer>; readonly publicKey: Uint8Array<ArrayBuffer>; readonly request: RequestCreateRequest; readonly writeSeed: Uint8Array<ArrayBuffer>; }

export function RequestPage() {
  const client = useClient();
  const [title, setTitle] = useState("");
  const [instructions, setInstructions] = useState("");
  const [fields, setFields] = useState<readonly DraftField[]>([{ help: "", label: "API key", required: true, type: "secret" }]);
  const [protection, setProtection] = useState<Protection>("second-key");
  const [passphrase, setPassphrase] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [ttl, setTtl] = useState<TtlSeconds>(3600);
  const [state, setState] = useState<OperationState>("idle");
  const [verificationExpired, setVerificationExpired] = useState(false);
  const [artifacts, setArtifacts] = useState<readonly ShareArtifact[] | null>(null);
  const [pending, setPending] = useState<PendingRequest | null>(null);
  const [reconciling, setReconciling] = useState(false);
  const [saved, setSaved] = useState<Readonly<Record<string, boolean>>>({});
  const phrase = validatePassphrase(passphrase, confirmation);

  function updateField(index: number, key: "help" | "label" | "required", value: string | boolean): void {
    setFields(fields.map((field, fieldIndex) => fieldIndex === index ? { ...field, [key]: value } : field));
  }
  function selectFieldType(index: number, type: RequestFieldType): void {
    setFields(fields.map((field, fieldIndex) => fieldIndex !== index ? field : type === "instruction" ? { ...field, help: "", required: false, type } : { ...field, type }));
  }
  function selectTtl(value: number): void { if (value === 900 || value === 3600 || value === 28800 || value === 86400 || value === 259200 || value === 604800) setTtl(value); }

  function schema(publicKey: Uint8Array): RequestSchemaPayload {
    const schemaFields: RequestSchemaField[] = [];
    if (instructions.length > 0) schemaFields.push({ help: instructions, id: "instruction000", label: "Instructions", required: false, type: "instruction" });
    fields.forEach((field, index) => { schemaFields.push(field.type === "instruction" ? { help: "", id: requestFieldId(index), label: field.label, required: false, type: "instruction" } : { ...field, id: requestFieldId(index) }); });
    return { fields: schemaFields, kind: "request-schema", recipientPublicKey: encodeBase64Url(publicKey), title };
  }

  function finishCreate(value: PendingRequest, serverExpiresAt: number): void {
    const next: ShareArtifact[] = [{ channel: "Send this to the person who should answer.", id: "write", required: true, title: "Write link", value: artifactUrl("/r", { factorMode: value.factor.mode, kind: 3, recipientPublicKey: value.publicKey, requestLocator: value.locator, salt: value.factor.salt, serverExpiresAt, writeSeed: value.writeSeed }) }];
    if (value.factor.secondKey !== null) next.push({ channel: "Send separately from the write link.", id: "factor", required: true, title: "Second key", value: value.factor.secondKey });
    next.push({ channel: "Keep this private. It opens the response once.", id: "pickup", required: true, title: "Pickup link", value: artifactUrl("/i", { kind: 4, ownerSeed: value.ownerSeed, requestLocator: value.locator, serverExpiresAt }) });
    setReconciling(false); setPending(null); setArtifacts(next); setState("done");
  }

  async function create(): Promise<void> {
    setState("working");
    if (pending !== null) {
      setReconciling(true);
      const reconciled = await reconcileRequestCreation(client, pending.request.locator, pending.request.ownerToken, pending.request.settleNotAfter);
      if (reconciled.kind === "created") finishCreate(pending, reconciled.serverExpiresAt);
      else { setReconciling(false); setPending(null); setState("unavailable"); }
      return;
    }
    let permit;
    try { permit = await client.permitStatus(); }
    catch (error) {
      if (error instanceof ApiFailure && error.code === "creation_permit_required") {
        setVerificationExpired(true); setState("idle"); return;
      }
      setState(error instanceof ApiFailure && error.ambiguous ? "unknown" : "unavailable"); return;
    }
    try {
      const factor = await createFactor(protection, passphrase, confirmation);
      const locator = randomBytes(16);
      const writeSeed = randomBytes(32);
      const ownerSeed = randomBytes(32);
      const [writeKeys, ownerKeys] = await Promise.all([
        deriveRequestWriteKeys(writeSeed, factor.mode, factor.factor), deriveRequestOwnerKeys(ownerSeed)
      ]);
      const pair = await deriveHpkeKeyPair(ownerKeys.hpkeIkm);
      const requestSchema = schema(pair.publicKey);
      const clientNotAfter = permit.serverTime + ttl;
      const settleNotAfter = permit.serverTime + 60;
      const envelope = await encryptRequestSchemaEnvelope({ clientNotAfter, factorMode: factor.mode, payload: requestSchema, schemaKey: writeKeys.schemaKey });
      const request = {
        attemptId: encodeBase64Url(randomBytes(16)), clientNotAfter, envelope: encodeBase64Url(envelope), locator: encodeBase64Url(locator),
        ownerToken: encodeBase64Url(ownerKeys.ownerToken), settleNotAfter, ttlSeconds: ttl, writeToken: encodeBase64Url(writeKeys.writeToken)
      };
      const attempt: PendingRequest = { factor, locator, ownerSeed, publicKey: pair.publicKey, request, writeSeed };
      setPending(attempt);
      let serverExpiresAt: number;
      try { serverExpiresAt = (await client.createRequest(request)).serverExpiresAt; }
      catch (error) {
        if (!(error instanceof ApiFailure) || !error.ambiguous) {
          setReconciling(false);
          setPending(null);
          if (error instanceof ApiFailure && error.code === "creation_permit_required") {
            setVerificationExpired(true);
            setState("idle");
            return;
          }
          throw error;
        }
        setReconciling(true);
        const reconciled = await reconcileRequestCreation(client, request.locator, request.ownerToken, settleNotAfter);
        if (reconciled.kind !== "created") { setReconciling(false); setPending(null); setState("unavailable"); return; }
        serverExpiresAt = reconciled.serverExpiresAt;
      }
      finishCreate(attempt, serverExpiresAt);
    } catch { setReconciling(false); setState("unavailable"); }
  }

  const draft = validateRequestDraft(title, instructions, fields);
  if (artifacts !== null) {
    const complete = artifacts.every((artifact) => saved[artifact.id] === true);
    return <div className="task-page task-page--narrow"><PageIntro title="Request secret"><p>Your encrypted request is ready.</p></PageIntro><ShareSlip artifacts={artifacts} onSaved={(id, value) => { setSaved({ ...saved, [id]: value }); }} saved={saved} title="Request sealed" /><NavigationGuard when={!complete} /></div>;
  }
  return <div className="task-page task-page--narrow"><PageIntro title="Request secret"><p>Describe what you need. Verification happens only when you create the request.</p></PageIntro>
    <label><span>Request title</span><input onChange={(event) => { setTitle(event.currentTarget.value); }} value={title} /></label><label><span>Instructions</span><textarea onChange={(event) => { setInstructions(event.currentTarget.value); }} rows={3} value={instructions} /></label>
    <fieldset><legend>What should they send?</legend><div className="inline-fields">{fields.map((field, index) => <div key={index}><label><span>Label</span><input onChange={(event) => { updateField(index, "label", event.currentTarget.value); }} value={field.label} /></label><details><summary>More options</summary><label><span>Type</span><select onChange={(event) => { const value = event.currentTarget.value; selectFieldType(index, value === "short" || value === "long" || value === "instruction" ? value : "secret"); }} value={field.type}><option value="secret">Secret</option><option value="short">Short text</option><option value="long">Long text</option><option value="instruction">Instruction — label only</option></select></label>{field.type === "instruction" ? <StatusMessage>This item displays its label and does not collect an answer.</StatusMessage> : <><label><span>Help</span><input onChange={(event) => { updateField(index, "help", event.currentTarget.value); }} value={field.help} /></label><label><input checked={field.required} onChange={(event) => { updateField(index, "required", event.currentTarget.checked); }} type="checkbox" /> Required</label></>}{fields.length > 1 ? <button className="quiet-button" onClick={() => { setFields(fields.filter((_item, fieldIndex) => fieldIndex !== index)); }} type="button">Remove item</button> : null}</details></div>)}</div><button className="secondary-button" disabled={fields.length >= (instructions.length > 0 ? 31 : 32)} onClick={() => { setFields([...fields, { help: "", label: "", required: false, type: "secret" }]); }} type="button">Add another item</button></fieldset>
    <StatusMessage tone={draft.valid ? "success" : "warning"}>{draft.message}</StatusMessage>
    <ProtectionOptions onChange={setProtection} value={protection} />{protection === "passphrase" ? <PassphraseFields confirmation={confirmation} message={phrase.message} onConfirmation={setConfirmation} onPassphrase={setPassphrase} passphrase={passphrase} valid={phrase.valid} /> : null}
    <details className="advanced"><summary>More options</summary><label><span>Expires after</span><select onChange={(event) => { selectTtl(Number(event.currentTarget.value)); }} value={ttl}><option value={900}>15 minutes</option><option value={3600}>1 hour</option><option value={28800}>8 hours</option><option value={86400}>1 day</option><option value={259200}>3 days</option><option value={604800}>7 days</option></select></label></details>
    <button className="primary-button full-button" disabled={!draft.valid || (protection === "passphrase" && !phrase.valid) || state === "working" || verificationExpired} onClick={() => { void create(); }} type="button">{reconciling ? "Reconciling…" : state === "working" ? "Creating…" : "Create request"}</button>
    {reconciling ? <StatusMessage tone="warning"><strong>Reconciling creation.</strong> Keep this tab open. The exact in-memory capability and encrypted attempt cannot be recovered if you leave.</StatusMessage> : verificationExpired ? <div className="operation-notice"><strong>Verification expired.</strong><p>Copy your draft before verifying again. Leaving this page clears it.</p><a className="primary-button" href={gatePath("request")}>Verify again</a></div> : <OperationNotice state={state} />}
    <NavigationGuard description="Leaving now permanently loses the in-memory capability needed to confirm this creation attempt." title="Keep confirming creation?" when={pending !== null} />
  </div>;
}
