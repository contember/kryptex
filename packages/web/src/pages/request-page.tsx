import { useState } from "react";
import { Link } from "react-router";
import type { RequestFieldType, RequestSchemaField, RequestSchemaPayload } from "@kryptex/contracts/payloads";
import { isTtlSeconds, type TtlSeconds } from "@kryptex/contracts/protocol";
import type { RequestCreateRequest } from "@kryptex/contracts/api";
import { deriveHpkeKeyPair, deriveRequestOwnerKeys, deriveRequestWriteKeys, encodeBase64Url, encryptRequestSchemaEnvelope, randomBytes } from "@kryptex/crypto";
import { ApiFailure, reconcileRequestCreation } from "@kryptex/client";
import { useClient } from "../client-context";
import { artifactUrl, createFactor, requestFieldId, type FactorMaterial } from "../crypto-flow";
import { DEFAULT_TTL, TTL_CHOICES, VALUE_FIELD_TYPES, formatFieldType, formatTtl, isValueFieldType } from "../format";
import { AdvancedDisclosure, ExpiryNote, FieldHint, NavigationGuard, OperationNotice, PageIntro, PassphraseFields, PolicySummary, ProtectionOptions, ShareSlip, StatusMessage, type OperationState, type Protection, type ShareArtifact } from "../ui";
import { validatePassphrase, validateRequestDraft } from "../validation";
import { gatePath } from "../verification";

interface DraftField { readonly help: string; readonly label: string; readonly required: boolean; readonly type: RequestFieldType; }
interface PendingRequest { readonly factor: FactorMaterial; readonly locator: Uint8Array<ArrayBuffer>; readonly ownerSeed: Uint8Array<ArrayBuffer>; readonly publicKey: Uint8Array<ArrayBuffer>; readonly request: RequestCreateRequest; readonly writeSeed: Uint8Array<ArrayBuffer>; }

const PROTECTION_SUMMARY: Readonly<Record<Protection, string>> = {
  "link-only": "Anyone who has the write link can answer. Nothing else is needed.",
  "passphrase": "The other person also needs the passphrase you pick",
  "second-key": "The other person also needs the second key that Kryptex makes"
};

export function RequestPage() {
  const client = useClient();
  const [title, setTitle] = useState("");
  const [instructions, setInstructions] = useState("");
  const [fields, setFields] = useState<readonly DraftField[]>([{ help: "", label: "API key", required: true, type: "secret" }]);
  const [protection, setProtection] = useState<Protection>("link-only");
  const [passphrase, setPassphrase] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [ttl, setTtl] = useState<TtlSeconds>(DEFAULT_TTL);
  const [state, setState] = useState<OperationState>("idle");
  const [verificationExpired, setVerificationExpired] = useState(false);
  const [artifacts, setArtifacts] = useState<readonly ShareArtifact[] | null>(null);
  const [expiresAt, setExpiresAt] = useState<number | null>(null);
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
  function selectTtl(value: number): void { if (isTtlSeconds(value)) setTtl(value); }

  function schema(publicKey: Uint8Array): RequestSchemaPayload {
    const schemaFields: RequestSchemaField[] = [];
    if (instructions.length > 0) schemaFields.push({ help: instructions, id: "instruction000", label: "Instructions", required: false, type: "instruction" });
    fields.forEach((field, index) => { schemaFields.push(field.type === "instruction" ? { help: "", id: requestFieldId(index), label: field.label, required: false, type: "instruction" } : { ...field, id: requestFieldId(index) }); });
    return { fields: schemaFields, kind: "request-schema", recipientPublicKey: encodeBase64Url(publicKey), title };
  }

  function finishCreate(value: PendingRequest, serverExpiresAt: number): void {
    const next: ShareArtifact[] = [{ channel: "Send this to the person who should answer. They can fill it in once.", id: "write", required: true, shareable: true, title: "Write link", value: artifactUrl("/r", { factorMode: value.factor.mode, kind: 3, recipientPublicKey: value.publicKey, requestLocator: value.locator, salt: value.factor.salt, serverExpiresAt, writeSeed: value.writeSeed }) }];
    if (value.factor.secondKey !== null) next.push({ channel: "Send this a different way than the write link: in a call, in person, or in a chat on another device.", id: "factor", required: true, title: "Second key", value: value.factor.secondKey });
    next.push({ channel: "Keep this for yourself. Open it to wait for the answer. The page checks on its own, and the answer can be opened only once.", id: "pickup", openLabel: "Open", required: true, title: "Pickup link", value: artifactUrl("/i", { kind: 4, ownerSeed: value.ownerSeed, requestLocator: value.locator, serverExpiresAt }) });
    setReconciling(false); setPending(null); setArtifacts(next); setExpiresAt(serverExpiresAt); setState("done");
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
  const started = title.length > 0 || instructions.length > 0;
  /** Said under the disabled button, where a phone user is looking when nothing happens. */
  const blocked = !draft.valid ? draft.message : protection === "passphrase" && !phrase.valid ? `Passphrase: ${phrase.message}` : null;

  if (artifacts !== null) {
    const complete = artifacts.every((artifact) => saved[artifact.id] === true);
    return <div className="task-page task-page--wide">
      <PageIntro arrive step="Step 2 of 2 · share" title="Your request is ready">
        <p>The other person can answer once. Only your pickup link can open the answer. Kryptex cannot read it either.</p>
      </PageIntro>
      <ShareSlip
        artifacts={artifacts}
        note={expiresAt === null ? null : <ExpiryNote expiresAt={expiresAt} />}
        onSaved={(id, value) => { setSaved({ ...saved, [id]: value }); }}
        saved={saved}
        title="Send and keep these"
      >
        <Link className="secondary-button" reloadDocument to={gatePath("request")}>Create another request</Link>
      </ShareSlip>
      <NavigationGuard when={!complete} />
    </div>;
  }

  return <div className="task-page task-page--narrow">
    <PageIntro step="Step 1 of 2 · describe" title="Request a secret">
      <p>Say what you need. The other person fills in an encrypted form, so the secret never travels by email or chat.</p>
    </PageIntro>

    <div className="simple-form">
      <div className="field-block">
        <label><span>Request title</span><input onChange={(event) => { setTitle(event.currentTarget.value); }} placeholder="Production database credentials" value={title} /></label>
        <FieldHint>The other person sees this first. Say what you need and who you are.</FieldHint>
      </div>

      <div className="field-block">
        <label><span>Instructions</span><textarea onChange={(event) => { setInstructions(event.currentTarget.value); }} placeholder="Optional. Explain where to find the values, or how you will use them." rows={3} value={instructions} /></label>
        <FieldHint>Shown above the form. Anyone who can open the request can read it, so do not put secrets here.</FieldHint>
      </div>

      <section className="request-items">
        <h2>What should they send?</h2>
        <div className="request-item-list">
          {fields.map((field, index) => <div className="request-item" key={index}>
            <label><span>Label</span><input onChange={(event) => { updateField(index, "label", event.currentTarget.value); }} placeholder="API key" value={field.label} /></label>
            <p className="request-item__summary">{formatFieldType(field.type)}{field.type === "instruction" ? "" : field.required ? " · required" : " · optional"}</p>
            <details>
              <summary>Field options</summary>
              <div>
                <label className="field-block"><span>Type</span>
                  <select onChange={(event) => { const value = event.currentTarget.value; selectFieldType(index, isValueFieldType(value) ? value : "instruction"); }} value={field.type}>
                    {VALUE_FIELD_TYPES.map((type) => <option key={type} value={type}>{formatFieldType(type)}</option>)}
                    <option value="instruction">{formatFieldType("instruction")}</option>
                  </select>
                </label>
                {field.type === "instruction"
                  ? <FieldHint>This item only shows its label. It does not collect an answer.</FieldHint>
                  : <>
                    <label className="field-block"><span>Hint</span><input onChange={(event) => { updateField(index, "help", event.currentTarget.value); }} placeholder="Optional. Shown under the field." value={field.help} /></label>
                    <label className="check-label"><input checked={field.required} onChange={(event) => { updateField(index, "required", event.currentTarget.checked); }} type="checkbox" /><span>Required</span></label>
                  </>}
                {fields.length > 1 ? <div className="field-block__actions"><button className="quiet-button danger-text" onClick={() => { setFields(fields.filter((_item, fieldIndex) => fieldIndex !== index)); }} type="button">Remove this item</button></div> : null}
              </div>
            </details>
          </div>)}
        </div>
        <div className="field-block__actions">
          <button className="secondary-button" disabled={fields.length >= (instructions.length > 0 ? 31 : 32)} onClick={() => { setFields([...fields, { help: "", label: "", required: false, type: "secret" }]); }} type="button">Add another item</button>
        </div>
        {started && !draft.valid ? <StatusMessage tone="warning">{draft.message}</StatusMessage> : <FieldHint>{started ? draft.message : "Every item needs a label. The other person answers each one in a form."}</FieldHint>}
      </section>

      <div className="field-block">
        <label><span>Access ends after</span>
          <select onChange={(event) => { selectTtl(Number(event.currentTarget.value)); }} value={ttl}>
            {TTL_CHOICES.map((choice) => <option key={choice} value={choice}>{formatTtl(choice)}</option>)}
          </select>
        </label>
        <FieldHint>After this, the links stop working and Kryptex starts deleting the request and any answer. Failed deletion is retried.</FieldHint>
      </div>

      <PolicySummary items={[`Access ends after ${formatTtl(ttl)}`, "One answer only. The write link stops working after that.", PROTECTION_SUMMARY[protection]]} />

      <AdvancedDisclosure summary="Protection">
        <ProtectionOptions onChange={setProtection} value={protection} />
        {protection === "passphrase" ? <PassphraseFields confirmation={confirmation} message={phrase.message} onConfirmation={setConfirmation} onPassphrase={setPassphrase} passphrase={passphrase} strength={phrase.strength} valid={phrase.valid} /> : null}
      </AdvancedDisclosure>

      <button aria-describedby={blocked === null ? undefined : "create-blocked"} className="primary-button full-button" disabled={blocked !== null || state === "working" || verificationExpired} onClick={() => { void create(); }} type="button">{reconciling ? "Checking…" : state === "working" ? "Encrypting…" : "Encrypt and create request"}</button>
      {blocked === null || verificationExpired ? null : <p className="blocked-reason" id="create-blocked">{blocked}</p>}
      <p className="fine-print">The human check you passed covers one request. It never sees what you write.</p>
    </div>

    {reconciling
      ? <StatusMessage tone="warning"><strong>Checking whether the request was created.</strong> Keep this tab open. If you leave now, the request cannot be recovered.</StatusMessage>
      : verificationExpired
        ? <div className="operation-notice">
          <strong>The human check expired.</strong>
          <p>Copy your text somewhere safe first. Leaving this page clears it.</p>
          <a className="primary-button" href={gatePath("request")}>Do the check again</a>
        </div>
        : <OperationNotice creating state={state} />}
    <NavigationGuard description="If you leave now, the request cannot be recovered." title="Stay until the request is confirmed?" when={pending !== null} />
  </div>;
}
