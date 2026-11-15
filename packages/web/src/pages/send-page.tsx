import { useState } from "react";
import { Link } from "react-router";
import type { SendField, SendPayload, ValueFieldType } from "@kryptex/contracts/payloads";
import { isTtlSeconds, type TtlSeconds } from "@kryptex/contracts/protocol";
import type { SendCreateRequest } from "@kryptex/contracts/api";
import { deriveSendKeys, encodeBase64Url, encryptSendEnvelope, randomBytes } from "@kryptex/crypto";
import { ApiFailure, reconcileSendCreation } from "@kryptex/client";
import { useClient } from "../client-context";
import { artifactUrl, createFactor, type FactorMaterial } from "../crypto-flow";
import { DEFAULT_TTL, TTL_CHOICES, VALUE_FIELD_TYPES, formatFieldType, formatOpenAllowance, formatTtl, isMultilineField, isSensitiveField, isValueFieldType } from "../format";
import { AdvancedDisclosure, ExpiryNote, FieldHint, NavigationGuard, OperationNotice, PageIntro, PassphraseFields, PolicySummary, ProtectionOptions, ShareSlip, StatusMessage, type OperationState, type Protection, type ShareArtifact } from "../ui";
import { validatePassphrase, validateSendDraft } from "../validation";
import { gatePath } from "../verification";

interface PendingSend {
  readonly factor: FactorMaterial;
  readonly locator: Uint8Array<ArrayBuffer>;
  readonly manageSeed: Uint8Array<ArrayBuffer>;
  readonly request: SendCreateRequest;
  readonly sendSeed: Uint8Array<ArrayBuffer>;
}

const OPEN_CHOICES: readonly number[] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

const PROTECTION_SUMMARY: Readonly<Record<Protection, string>> = {
  "link-only": "Anyone who has the link can open it. Nothing else is needed.",
  "passphrase": "The recipient also needs the passphrase you pick",
  "second-key": "The recipient also needs the second key that Kryptex makes"
};

/** Only the recipient link offers the share sheet: the second key must travel another way, and the management link stays with the sender. */
export function sendShareArtifacts(links: { readonly recipient: string; readonly secondKey: string | null; readonly management: string }): readonly ShareArtifact[] {
  const artifacts: ShareArtifact[] = [{ channel: "Send this to the person who should get the secret.", id: "recipient", required: true, shareable: true, title: "Recipient link", value: links.recipient }];
  if (links.secondKey !== null) artifacts.push({ channel: "Send this a different way than the link: in a call, in person, or in a chat on another device. Never put it in the same message.", id: "factor", required: true, title: "Second key", value: links.secondKey });
  artifacts.push({ channel: "Keep this for yourself. It shows when the secret was opened and lets you shorten its time or revoke it.", id: "management", required: false, title: "Management link", value: links.management });
  return artifacts;
}

export function SendPage() {
  const client = useClient();
  const [mode, setMode] = useState<"text" | "fields">("text");
  const [text, setText] = useState("");
  const [fields, setFields] = useState<readonly SendField[]>([{ label: "API key", type: "secret", value: "" }]);
  const [protection, setProtection] = useState<Protection>("second-key");
  const [passphrase, setPassphrase] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [ttl, setTtl] = useState<TtlSeconds>(DEFAULT_TTL);
  const [retrievals, setRetrievals] = useState(1);
  const [state, setState] = useState<OperationState>("idle");
  const [verificationExpired, setVerificationExpired] = useState(false);
  const [artifacts, setArtifacts] = useState<readonly ShareArtifact[] | null>(null);
  const [expiresAt, setExpiresAt] = useState<number | null>(null);
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
  function selectFieldType(index: number, type: ValueFieldType): void {
    setFields(fields.map((field, fieldIndex) => fieldIndex === index ? { ...field, type } : field));
  }
  function selectTtl(value: number): void { if (isTtlSeconds(value)) setTtl(value); }

  function finishCreate(value: PendingSend, serverExpiresAt: number): void {
    const next = sendShareArtifacts({
      management: artifactUrl("/m", { kind: 2, locator: value.locator, manageSeed: value.manageSeed, serverExpiresAt }),
      recipient: artifactUrl("/s", { factorMode: value.factor.mode, kind: 1, salt: value.factor.salt, sendSeed: value.sendSeed, serverExpiresAt }),
      secondKey: value.factor.secondKey
    });
    setReconciling(false); setPending(null); setArtifacts(next); setExpiresAt(serverExpiresAt); setState("done");
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
        setVerificationExpired(true);
        setState("idle");
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
            setVerificationExpired(true);
            setState("idle");
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
  const started = mode === "text" ? text.length > 0 : fields.some((field) => field.value.length > 0);
  /** Said under the disabled button, where a phone user is looking when nothing happens. */
  const blocked = !draft.valid ? draft.message : protection === "passphrase" && !phrase.valid ? `Passphrase: ${phrase.message}` : null;

  if (artifacts !== null) {
    const complete = artifacts.every((artifact) => saved[artifact.id] === true);
    return <div className="task-page task-page--wide">
      <PageIntro arrive step="Step 2 of 2 · share" title="Your secret is ready">
        <p>Kryptex stored it encrypted and cannot read it. What opens it is on this page and nowhere else.</p>
      </PageIntro>
      <ShareSlip
        artifacts={artifacts}
        note={expiresAt === null ? null : <ExpiryNote expiresAt={expiresAt} />}
        onSaved={(id, value) => { setSaved({ ...saved, [id]: value }); }}
        saved={saved}
        title="Send and keep these"
      >
        <Link className="secondary-button" reloadDocument to={gatePath("send")}>Send another secret</Link>
      </ShareSlip>
      <NavigationGuard when={!complete} />
    </div>;
  }

  return <div className="task-page task-page--narrow">
    <PageIntro step="Step 1 of 2 · write" title="Send a secret">
      <p>Your browser encrypts the secret before anything is sent. Kryptex never sees what you write.</p>
    </PageIntro>

    <div className="simple-form">
      <fieldset className="compact-options">
        <legend>What are you sending?</legend>
        <label><input checked={mode === "text"} name="content" onChange={() => { setMode("text"); }} type="radio" /><span>A single text</span></label>
        <label><input checked={mode === "fields"} name="content" onChange={() => { setMode("fields"); }} type="radio" /><span>Several labelled values</span></label>
      </fieldset>

      {mode === "text"
        ? <div className="field-block">
          <label><span>Secret</span><textarea autoComplete="off" onChange={(event) => { setText(event.currentTarget.value); }} rows={7} spellCheck={false} value={text} /></label>
          {started && !draft.valid ? <StatusMessage tone="warning">{draft.message}</StatusMessage> : <FieldHint>{started ? draft.message : "Paste a password, a code or a note. Nothing is sent while you type."}</FieldHint>}
        </div>
        : <div className="field-block">
          <span className="field-block__label">Values</span>
          <div className="inline-fields">
            {fields.map((field, index) => <div key={index}>
              <label><span>Label</span><input onChange={(event) => { updateField(index, "label", event.currentTarget.value); }} placeholder="Database password" value={field.label} /></label>
              <label><span>Value</span>
                {isMultilineField(field.type)
                  ? <textarea autoComplete="off" onChange={(event) => { updateField(index, "value", event.currentTarget.value); }} rows={4} spellCheck={!isSensitiveField(field.type)} value={field.value} />
                  : <input autoComplete="off" onChange={(event) => { updateField(index, "value", event.currentTarget.value); }} spellCheck={!isSensitiveField(field.type)} type={isSensitiveField(field.type) ? "password" : "text"} value={field.value} />}
              </label>
              {fields.length > 1 ? <button className="quiet-button" onClick={() => { setFields(fields.filter((_field, fieldIndex) => fieldIndex !== index)); }} type="button">Remove</button> : null}
              <details className="inline-fields__options">
                <summary>Type: {formatFieldType(field.type)}</summary>
                <div>
                  <label className="field-block"><span>Value type</span>
                    <select onChange={(event) => { const value = event.currentTarget.value; if (isValueFieldType(value)) selectFieldType(index, value); }} value={field.type}>
                      {VALUE_FIELD_TYPES.map((type) => <option key={type} value={type}>{formatFieldType(type)}</option>)}
                    </select>
                  </label>
                  <FieldHint>A secret stays hidden while you type. Pick a long type for keys, certificates or anything with several lines.</FieldHint>
                </div>
              </details>
            </div>)}
          </div>
          <div className="field-block__actions">
            <button className="secondary-button" disabled={fields.length >= 32} onClick={() => { setFields([...fields, { label: "", type: "secret", value: "" }]); }} type="button">Add another value</button>
          </div>
          {started && !draft.valid ? <StatusMessage tone="warning">{draft.message}</StatusMessage> : <FieldHint>{started ? draft.message : "Each value gets its own label, so the recipient knows what is what."}</FieldHint>}
        </div>}

      <div className="field-block">
        <label><span>Access ends after</span>
          <select onChange={(event) => { selectTtl(Number(event.currentTarget.value)); }} value={ttl}>
            {TTL_CHOICES.map((choice) => <option key={choice} value={choice}>{formatTtl(choice)}</option>)}
          </select>
        </label>
        <FieldHint>After this, the link stops working and Kryptex starts deleting the encrypted copy. Failed deletion is retried. Shorter is safer.</FieldHint>
      </div>

      <PolicySummary items={[`Access ends after ${formatTtl(ttl)}`, formatOpenAllowance(retrievals), PROTECTION_SUMMARY[protection]]} />

      <AdvancedDisclosure summary="Protection and opens">
        <ProtectionOptions onChange={setProtection} value={protection} />
        {protection === "passphrase" ? <PassphraseFields confirmation={confirmation} message={phrase.message} onConfirmation={setConfirmation} onPassphrase={setPassphrase} passphrase={passphrase} strength={phrase.strength} valid={phrase.valid} /> : null}
        <div className="field-block">
          <label><span>Maximum opens</span>
            <select onChange={(event) => { setRetrievals(Number(event.currentTarget.value)); }} value={retrievals}>
              {OPEN_CHOICES.map((choice) => <option key={choice} value={choice}>{choice}</option>)}
            </select>
          </label>
          <FieldHint>This counts each time the encrypted secret is sent to a browser, not how many people read it. Keep 1 unless the recipient may need a second try.</FieldHint>
        </div>
      </AdvancedDisclosure>

      <button aria-describedby={blocked === null ? undefined : "create-blocked"} className="primary-button full-button" disabled={blocked !== null || state === "working" || verificationExpired} onClick={() => { void create(); }} type="button">{reconciling ? "Checking…" : state === "working" ? "Encrypting…" : "Encrypt and create link"}</button>
      {blocked === null || verificationExpired ? null : <p className="blocked-reason" id="create-blocked">{blocked}</p>}
      <p className="fine-print">The human check you passed covers one link. It never sees your secret.</p>
    </div>

    {reconciling
      ? <StatusMessage tone="warning"><strong>Checking whether the link was created.</strong> Keep this tab open. If you leave now, the link cannot be recovered.</StatusMessage>
      : verificationExpired
        ? <div className="operation-notice">
          <strong>The human check expired.</strong>
          <p>Copy your text somewhere safe first. Leaving this page clears it.</p>
          <a className="primary-button" href={gatePath("send")}>Do the check again</a>
        </div>
        : <OperationNotice creating state={state} />}
    <NavigationGuard description="If you leave now, the link cannot be recovered." title="Stay until the link is confirmed?" when={pending !== null} />
  </div>;
}
