import { useState } from "react";
import type { RequestResponsePayload, RequestSchemaPayload } from "@kryptex/contracts/payloads";
import { decodeBase64Url, decryptRequestSchemaEnvelope, deriveRequestWriteKeys, encodeBase64Url, receiptBase64Url, receiptDisplay, sealRequestResponse } from "@kryptex/crypto";
import { useClient } from "../client-context";
import { checkedResponseExpiry, classifyReadFailure, classifySubmitFailure, consumeBundle, exactEnvelopeForRetry, factorFromInput } from "../crypto-flow";
import { isMultilineField, isSensitiveField } from "../format";
import type { FragmentCapture } from "../fragment";
import { FactorInput, FieldHint, FragmentNotice, OperationNotice, PageIntro, StatusMessage, normalizedFactorInput, type OperationState } from "../ui";
import { validateRequestAnswers } from "../validation";

interface OpenedSchema { readonly clientNotAfter: number; readonly digest: Uint8Array<ArrayBuffer>; readonly schema: RequestSchemaPayload; readonly serverExpiresAt: number; readonly writeToken: string; }

export function WriterPage({ capture }: { readonly capture: FragmentCapture }) {
  const client = useClient();
  const [bundle] = useState(() => consumeBundle(capture, 3));
  const [factor, setFactor] = useState("");
  const [opened, setOpened] = useState<OpenedSchema | null>(null);
  const [answers, setAnswers] = useState<Readonly<Record<string, string>>>({});
  const [envelope, setEnvelope] = useState<string | null>(null);
  const [receipt, setReceipt] = useState<string | null>(null);
  const [receiptMatch, setReceiptMatch] = useState<boolean | null>(null);
  const [confirmed, setConfirmed] = useState(false);
  const [state, setState] = useState<OperationState>("idle");

  async function inspect(): Promise<void> {
    if (bundle?.kind !== 3) return;
    setState("working");
    try {
      const factorBytes = await factorFromInput(bundle.factorMode, bundle.salt, normalizedFactorInput(bundle.factorMode, factor));
      const keys = await deriveRequestWriteKeys(bundle.writeSeed, bundle.factorMode, factorBytes);
      const response = await client.requestSchema({ locator: encodeBase64Url(bundle.requestLocator), writeToken: encodeBase64Url(keys.writeToken) });
      const serverExpiresAt = checkedResponseExpiry(bundle.serverExpiresAt, response.metadata.serverExpiresAt);
      const result = await decryptRequestSchemaEnvelope(response.bytes, keys.schemaKey, bundle.factorMode, bundle.recipientPublicKey, serverExpiresAt, Math.floor(Date.now() / 1_000));
      setOpened({ clientNotAfter: result.header.clientNotAfter, digest: result.header.schemaDigest, schema: result.payload, serverExpiresAt, writeToken: encodeBase64Url(keys.writeToken) });
      setState("done");
    } catch (error) { setState(classifyReadFailure(error)); }
  }

  async function submit(): Promise<void> {
    if (bundle?.kind !== 3 || opened === null) return;
    setState("working");
    try {
      const exact = await exactEnvelopeForRetry(envelope, async () => {
        const payload: RequestResponsePayload = { answers: opened.schema.fields.filter((field) => field.type !== "instruction").map((field) => ({ id: field.id, value: answers[field.id] ?? "" })), kind: "request-response", schema: opened.schema };
        return encodeBase64Url(await sealRequestResponse({ expectedClientNotAfter: opened.clientNotAfter, payload, recipientPublicKey: bundle.recipientPublicKey, requestLocator: bundle.requestLocator, schemaDigest: opened.digest }));
      });
      if (envelope === null) setEnvelope(exact);
      const bytes = decodeBase64Url(exact);
      const localBase64 = await receiptBase64Url(bytes);
      setReceipt(await receiptDisplay(bytes));
      const response = await client.submitRequest({ envelope: exact, locator: encodeBase64Url(bundle.requestLocator), writeToken: opened.writeToken });
      setReceiptMatch(response.receipt === localBase64);
      setState(response.receipt === localBase64 ? "done" : "unknown");
    } catch (error) { setState(classifySubmitFailure(error)); }
  }

  const answerValidation = opened === null ? { message: "", valid: false } : validateRequestAnswers(opened.schema.fields, answers);
  const sealed = envelope !== null;
  const started = Object.values(answers).some((value) => value.length > 0);

  return <div className="task-page task-page--narrow">
    <PageIntro title="Someone is asking you for information">
      <p>Reading the request sends nothing. Your answer is encrypted in this browser and can only be opened by the person who created the request.</p>
    </PageIntro>
    <FragmentNotice capture={capture} />

    {opened === null
      ? <div className="simple-form">
        {bundle?.kind === 3 && bundle.factorMode !== 0
          ? <FactorInput mode={bundle.factorMode === 1 ? 1 : 2} onChange={setFactor} value={factor} />
          : null}
        {bundle?.kind === 3
          ? <button className="primary-button full-button" disabled={state === "working"} onClick={() => { void inspect(); }} type="button">{state === "working" ? "Opening…" : "Open the request"}</button>
          : capture.fragmentBytes === null
            ? null
            : <StatusMessage tone="danger">This link is not a valid Kryptex request link. Ask for the whole link again — messengers often cut off the part after the <span className="mono">#</span>.</StatusMessage>}
      </div>
      : <>
        <section className="requester-content">
          <p className="eyebrow">Provided by requester</p>
          <h2>{opened.schema.title}</h2>
          {sealed ? <StatusMessage tone="warning">Your answers are sealed into one encrypted response. Editing is off, and any retry sends exactly the same bytes.</StatusMessage> : null}
          <div className="simple-form">
            {opened.schema.fields.map((field) => field.type === "instruction"
              ? <div className="requester-note" key={field.id}>
                <strong>{field.label}</strong>
                {field.help.length === 0 ? null : <p>{field.help}</p>}
              </div>
              : <div className="field-block" key={field.id}>
                <label>
                  <span>{field.label}{field.required ? "" : " (optional)"}</span>
                  {isMultilineField(field.type)
                    ? <textarea disabled={sealed} onChange={(event) => { setAnswers({ ...answers, [field.id]: event.currentTarget.value }); }} rows={4} spellCheck={!isSensitiveField(field.type)} value={answers[field.id] ?? ""} />
                    : <input autoComplete="off" disabled={sealed} onChange={(event) => { setAnswers({ ...answers, [field.id]: event.currentTarget.value }); }} spellCheck={!isSensitiveField(field.type)} type={isSensitiveField(field.type) ? "password" : "text"} value={answers[field.id] ?? ""} />}
                </label>
                {field.help.length === 0 ? null : <span className="field-hint field-hint--requester">{field.help}</span>}
              </div>)}
          </div>
        </section>

        {receipt === null
          ? <div className="simple-form">
            {sealed ? null : started && !answerValidation.valid ? <StatusMessage tone="warning">{answerValidation.message}</StatusMessage> : <FieldHint>{started ? answerValidation.message : "Fill in the answers. Nothing is sent while you type."}</FieldHint>}
            <label className="check-label">
              <input checked={confirmed} disabled={sealed} onChange={(event) => { setConfirmed(event.currentTarget.checked); }} type="checkbox" />
              <span>I checked my answers. Only one response can win, and this link stops working once a response is accepted.</span>
            </label>
            <button className="primary-button full-button" disabled={!answerValidation.valid || !confirmed || state === "working"} onClick={() => { void submit(); }} type="button">{state === "working" ? "Sending…" : envelope === null ? "Send the answer" : "Send the identical answer again"}</button>
          </div>
          : <>
            {receiptMatch === true ? <StatusMessage tone="success">Answer sent. The person who asked can now open it once. Nothing else is needed from you.</StatusMessage> : null}
            <div className="fingerprint">
              <span>Receipt for your answer</span>
              <strong>{receipt}</strong>
              <p>{receiptMatch === true ? "The service returned the same receipt, so both sides hold identical ciphertext." : receiptMatch === false ? "The service returned a different receipt. Treat the submission as unconfirmed and keep this value." : "The submission is unconfirmed. Keep this value."} Compare all 64 characters through a separate channel if it matters. A match only proves both browsers hold the same ciphertext bytes — it does not authenticate the writer, the plaintext, or the service.</p>
            </div>
            {state === "unknown" ? <button className="secondary-button" onClick={() => { void submit(); }} type="button">Send the identical answer again</button> : null}
          </>}
      </>}
    <OperationNotice state={state} />
  </div>;
}
