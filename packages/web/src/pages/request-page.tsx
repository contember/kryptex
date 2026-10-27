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
  "link-only": "Anyone who has the write link can answer — nothing else is needed",
  "passphrase": "The other person also needs the passphrase you chose",
  "second-key": "The other person also needs the second key Kryptex generates"
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
    const next: ShareArtifact[] = [{ channel: "Send this to the person who should answer. They can fill it in once.", id: "write", required: true, title: "Write link", value: artifactUrl("/r", { factorMode: value.factor.mode, kind: 3, recipientPublicKey: value.publicKey, requestLocator: value.locator, salt: value.factor.salt, serverExpiresAt, writeSeed: value.writeSeed }) }];
    if (value.factor.secondKey !== null) next.push({ channel: "Send through a different channel than the write link — a call, a chat on another device, in person.", id: "factor", required: true, title: "Second key", value: value.factor.secondKey });
    next.push({ channel: "Keep this for yourself. Open it to watch for the answer — the page refreshes on its own and releasing the answer works once.", id: "pickup", openLabel: "Open", required: true, title: "Pickup link", value: artifactUrl("/i", { kind: 4, ownerSeed: value.ownerSeed, requestLocator: value.locator, serverExpiresAt }) });
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

  if (artifacts !== null) {
    const complete = artifacts.every((artifact) => saved[artifact.id] === true);
    return <div className="task-page task-page--wide">
      <PageIntro step="Step 2 of 2 · hand over" title="The request is ready">
        <p>The other person fills it in once. Their answer is encrypted for your pickup link alone — the service cannot read it either.</p>
      </PageIntro>
      <ShareSlip
        artifacts={artifacts}
        note={expiresAt === null ? null : <ExpiryNote expiresAt={expiresAt} />}
        onSaved={(id, value) => { setSaved({ ...saved, [id]: value }); }}
        saved={saved}
        title="Request sealed"
      >
        <Link className="secondary-button" reloadDocument to={gatePath("request")}>Create another request</Link>
      </ShareSlip>
      <NavigationGuard when={!complete} />
    </div>;
  }

  return <div className="task-page task-page--narrow">
    <PageIntro step="Step 1 of 2 · describe" title="Request a secret">
      <p>Describe what you need. The other person answers through an encrypted form, so nothing sensitive travels by mail or chat.</p>
    </PageIntro>

    <div className="simple-form">
      <div className="field-block">
        <label><span>Request title</span><input onChange={(event) => { setTitle(event.currentTarget.value); }} placeholder="Production database credentials" value={title} /></label>
        <FieldHint>The other person sees this first. Say what you need and who you are.</FieldHint>
      </div>

      <div className="field-block">
        <label><span>Instructions</span><textarea onChange={(event) => { setInstructions(event.currentTarget.value); }} placeholder="Optional. Explain where to find the values, or how you will use them." rows={3} value={instructions} /></label>
        <FieldHint>Shown above the form as plain text. Do not put secrets here — this text travels with the link.</FieldHint>
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
                    <label className="field-block"><span>Help</span><input onChange={(event) => { updateField(index, "help", event.currentTarget.value); }} placeholder="Optional hint shown under the field" value={field.help} /></label>
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
        <FieldHint>When the time is up, the service closes access and starts deleting the stored request and answer. Failed deletion is retried.</FieldHint>
      </div>

      <PolicySummary items={[`Access ends after ${formatTtl(ttl)}`, "One answer only — the write link stops working once it is used", PROTECTION_SUMMARY[protection]]} />

      <AdvancedDisclosure summary="Protection">
        <ProtectionOptions onChange={setProtection} value={protection} />
        {protection === "passphrase" ? <PassphraseFields confirmation={confirmation} message={phrase.message} onConfirmation={setConfirmation} onPassphrase={setPassphrase} passphrase={passphrase} strength={phrase.strength} valid={phrase.valid} /> : null}
      </AdvancedDisclosure>

      <button className="primary-button full-button" disabled={!draft.valid || (protection === "passphrase" && !phrase.valid) || state === "working" || verificationExpired} onClick={() => { void create(); }} type="button">{reconciling ? "Confirming…" : state === "working" ? "Creating…" : "Create request"}</button>
      <p className="fine-print">Creating checks that you are human once. The request itself never reaches that check.</p>
    </div>

    {reconciling
      ? <StatusMessage tone="warning"><strong>Confirming the result.</strong> Keep this tab open. The encrypted attempt lives only in this page and cannot be rebuilt if you leave.</StatusMessage>
      : verificationExpired
        ? <div className="operation-notice">
          <strong>The human check expired.</strong>
          <p>Copy your draft somewhere safe first — leaving this page clears it.</p>
          <a className="primary-button" href={gatePath("request")}>Check again</a>
        </div>
        : <OperationNotice state={state} />}
    <NavigationGuard description="Leaving now permanently loses the key this page needs to confirm the attempt." title="Keep confirming this request?" when={pending !== null} />
  </div>;
}
