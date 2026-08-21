import { useState } from "react";
import { Link } from "react-router";
import type { SendField, SendPayload } from "@kryptex/contracts/payloads";
import { isTtlSeconds, type TtlSeconds } from "@kryptex/contracts/protocol";
import type { SendCreateRequest } from "@kryptex/contracts/api";
import { deriveSendKeys, encodeBase64Url, encryptSendEnvelope, randomBytes } from "@kryptex/crypto";
import { ApiFailure } from "../api-client";
import { useClient } from "../client-context";
import { artifactUrl, createFactor, reconcileSendCreation, type FactorMaterial } from "../crypto-flow";
import { DEFAULT_TTL, TTL_CHOICES, formatOpenAllowance, formatTtl } from "../format";
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

const PROTECTION_SUMMARY: Readonly<Record<Protection, string>> = {
  "link-only": "Anyone who has the link can open it — nothing else is needed",
  "passphrase": "The recipient also needs the passphrase you chose",
  "second-key": "The recipient also needs the second key Kryptex generates"
};

export function SendPage() {
  const client = useClient();
  const [mode, setMode] = useState<"text" | "fields">("text");
  const [text, setText] = useState("");
  const [fields, setFields] = useState<readonly SendField[]>([{ concealed: true, label: "API key", value: "" }]);
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
  function selectTtl(value: number): void { if (isTtlSeconds(value)) setTtl(value); }

  function finishCreate(value: PendingSend, serverExpiresAt: number): void {
    const next: ShareArtifact[] = [{ channel: "Send this link to the recipient.", id: "recipient", required: true, title: "Recipient link", value: artifactUrl("/s", { factorMode: value.factor.mode, kind: 1, salt: value.factor.salt, sendSeed: value.sendSeed, serverExpiresAt }) }];
    if (value.factor.secondKey !== null) next.push({ channel: "Send through a different channel — a call, a chat on another device, in person. Never append it to the link.", id: "factor", required: true, title: "Second key", value: value.factor.secondKey });
    next.push({ channel: "Keep this for yourself. It lets you check the status, shorten the expiry, or revoke the secret.", id: "management", required: false, title: "Management link", value: artifactUrl("/m", { kind: 2, locator: value.locator, manageSeed: value.manageSeed, serverExpiresAt }) });
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

  if (artifacts !== null) {
    const complete = artifacts.every((artifact) => saved[artifact.id] === true);
    return <div className="task-page task-page--wide">
      <PageIntro step="Step 2 of 2 · hand over" title="The secret is sealed">
        <p>Kryptex stored an encrypted envelope it cannot read. Everything needed to open it is on this page and nowhere else.</p>
      </PageIntro>
      <ShareSlip
        artifacts={artifacts}
        note={expiresAt === null ? null : <ExpiryNote expiresAt={expiresAt} />}
        onSaved={(id, value) => { setSaved({ ...saved, [id]: value }); }}
        saved={saved}
        title="Secret sealed"
      >
        <Link className="secondary-button" reloadDocument to={gatePath("send")}>Send another secret</Link>
      </ShareSlip>
      <NavigationGuard when={!complete} />
    </div>;
  }

  return <div className="task-page task-page--narrow">
    <PageIntro step="Step 1 of 2 · compose" title="Send a secret">
      <p>Write the secret below. This browser encrypts it before anything leaves the page, so the service never sees the readable text.</p>
    </PageIntro>

    <div className="simple-form">
      <fieldset className="compact-options">
        <legend>What are you sending?</legend>
        <label><input checked={mode === "text"} name="content" onChange={() => { setMode("text"); }} type="radio" /><span>One text</span></label>
        <label><input checked={mode === "fields"} name="content" onChange={() => { setMode("fields"); }} type="radio" /><span>Labelled values</span></label>
      </fieldset>

      {mode === "text"
        ? <div className="field-block">
          <label><span>Secret</span><textarea autoComplete="off" onChange={(event) => { setText(event.currentTarget.value); }} rows={7} spellCheck={false} value={text} /></label>
          {started && !draft.valid ? <StatusMessage tone="warning">{draft.message}</StatusMessage> : <FieldHint>{started ? draft.message : "Paste a password, token, or note. Nothing is sent while you type."}</FieldHint>}
        </div>
        : <div className="field-block">
          <span className="field-block__label">Secret values</span>
          <div className="inline-fields">
            {fields.map((field, index) => <div key={index}>
              <label><span>Label</span><input onChange={(event) => { updateField(index, "label", event.currentTarget.value); }} placeholder="Database password" value={field.label} /></label>
              <label><span>Value</span><input autoComplete="off" onChange={(event) => { updateField(index, "value", event.currentTarget.value); }} spellCheck={false} type="password" value={field.value} /></label>
              {fields.length > 1 ? <button className="quiet-button" onClick={() => { setFields(fields.filter((_field, fieldIndex) => fieldIndex !== index)); }} type="button">Remove</button> : null}
            </div>)}
          </div>
          <div className="field-block__actions">
            <button className="secondary-button" disabled={fields.length >= 32} onClick={() => { setFields([...fields, { concealed: true, label: "", value: "" }]); }} type="button">Add value</button>
          </div>
          {started && !draft.valid ? <StatusMessage tone="warning">{draft.message}</StatusMessage> : <FieldHint>{started ? draft.message : "Each value gets its own label, so the recipient knows what is what."}</FieldHint>}
        </div>}

      <div className="field-block">
        <label><span>Delete after</span>
          <select onChange={(event) => { selectTtl(Number(event.currentTarget.value)); }} value={ttl}>
            {TTL_CHOICES.map((choice) => <option key={choice} value={choice}>{formatTtl(choice)}</option>)}
          </select>
        </label>
        <FieldHint>When the time is up, the stored data is deleted whether or not anyone opened it. Shorter is safer.</FieldHint>
      </div>

      <PolicySummary items={[`Deleted after ${formatTtl(ttl)}`, formatOpenAllowance(retrievals), PROTECTION_SUMMARY[protection]]} />

      <AdvancedDisclosure summary="Protection and opens">
        <ProtectionOptions onChange={setProtection} value={protection} />
        {protection === "passphrase" ? <PassphraseFields confirmation={confirmation} message={phrase.message} onConfirmation={setConfirmation} onPassphrase={setPassphrase} passphrase={passphrase} strength={phrase.strength} valid={phrase.valid} /> : null}
        <div className="field-block">
          <label><span>Maximum opens</span><input max={10} min={1} onChange={(event) => { setRetrievals(event.currentTarget.valueAsNumber); }} type="number" value={retrievals} /></label>
          <FieldHint>Counts released copies, not people who read them. One is right unless the recipient may need a retry.</FieldHint>
        </div>
      </AdvancedDisclosure>

      <button className="primary-button full-button" disabled={!draft.valid || (protection === "passphrase" && !phrase.valid) || state === "working" || verificationExpired} onClick={() => { void create(); }} type="button">{reconciling ? "Confirming…" : state === "working" ? "Sealing…" : "Seal and create link"}</button>
      <p className="fine-print">Sealing checks that you are human once. The secret itself never reaches that check.</p>
    </div>

    {reconciling
      ? <StatusMessage tone="warning"><strong>Confirming the result.</strong> Keep this tab open. The encrypted attempt lives only in this page and cannot be rebuilt if you leave.</StatusMessage>
      : verificationExpired
        ? <div className="operation-notice">
          <strong>The human check expired.</strong>
          <p>Copy your draft somewhere safe first — leaving this page clears it.</p>
          <a className="primary-button" href={gatePath("send")}>Check again</a>
        </div>
        : <OperationNotice state={state} />}
    <NavigationGuard description="Leaving now permanently loses the key this page needs to confirm the attempt." title="Keep confirming this secret?" when={pending !== null} />
  </div>;
}
