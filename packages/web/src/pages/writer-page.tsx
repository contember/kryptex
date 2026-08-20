import { useRef, useState } from "react";

import type { FragmentCapture } from "../fragment";
import type { PreviewEnvelope, PreviewRequestField } from "../preview-adapter";
import { usePreviewOperation } from "../preview-hooks";
import { createPreviewEnvelope, submitIdenticalEnvelope } from "../preview-transitions";
import { AmbiguousNotice, FragmentNotice, OperationNotice, PageIntro, PreviewMark, StatusMessage, type OperationState } from "../ui";
import { isValidCrockfordFactor } from "../validation";

function AnswerField({ field, value, onChange }: { readonly field: PreviewRequestField; readonly value: string; readonly onChange: (value: string) => void }) {
  return <label className="field-block">
    <span>{field.label} <small>{field.required ? "required" : "optional"}</small></span>
    {field.type === "long"
      ? <textarea onChange={(event) => { onChange(event.currentTarget.value); }} value={value} />
      : <input autoComplete="off" onChange={(event) => { onChange(event.currentTarget.value); }} spellCheck={false} type={field.type === "secret" ? "password" : "text"} value={value} />}
    {field.help.length > 0 ? <small>{field.help}</small> : null}
  </label>;
}

export function WriterPage({ capture }: { readonly capture: FragmentCapture }) {
  const operation = usePreviewOperation();
  const schema = operation.adapter.readRequestSchema();
  const [factor, setFactor] = useState("");
  const [loaded, setLoaded] = useState(false);
  const [answers, setAnswers] = useState<Readonly<Record<number, string>>>({});
  const [submitted, setSubmitted] = useState(false);
  const [state, setState] = useState<OperationState>("idle");
  const envelopeRef = useRef<PreviewEnvelope | null>(null);
  const factorValid = isValidCrockfordFactor(factor);
  const complete = schema.fields.every((field) => !field.required || (answers[field.id] ?? "").length > 0);

  async function load(): Promise<void> {
    setState("working");
    try {
      const result = await operation.run("inspect");
      if (result.outcome === "waiting" || result.outcome === "pending") setState("waiting");
      else if (result.outcome === "unavailable") setState("unavailable");
      else { setLoaded(true); setState("done"); }
    } catch {
      setState("unavailable");
    }
  }

  async function submit(): Promise<void> {
    setState("working");
    const existingEnvelope = envelopeRef.current;
    const envelope = existingEnvelope ?? createPreviewEnvelope();
    envelopeRef.current = envelope;
    try {
      await submitIdenticalEnvelope(operation.adapter, envelope);
      setSubmitted(true);
      setState("done");
    } catch {
      setState("unknown");
    }
  }

  if (submitted) return <div className="task-page task-page--narrow">
    <PageIntro title="Sent"><p>Your encrypted response was accepted.</p></PageIntro>
    <PreviewMark />
    <StatusMessage tone="success">This request cannot be used again.</StatusMessage>
    <div className="fingerprint"><span>Receipt</span><strong>DEMO FINGERPRINT — NOT COMPUTED</strong></div>
  </div>;

  return <div className="task-page task-page--narrow">
    <PageIntro title={loaded ? schema.title : "Open request"}><p>{loaded ? "Complete the requested items, then send once." : "Reviewing the request does not use its one response."}</p></PageIntro>
    <PreviewMark />
    <FragmentNotice capture={capture} />
    {loaded
      ? <form className="simple-form" onSubmit={(event) => { event.preventDefault(); void submit(); }}>
          {schema.instructions.length > 0 ? <div className="request-instructions"><small>From requester</small><p>{schema.instructions}</p></div> : null}
          {schema.fields.map((field) => <AnswerField field={field} key={field.id} onChange={(value) => { setAnswers((current) => ({ ...current, [field.id]: value })); }} value={answers[field.id] ?? ""} />)}
          {state === "unknown"
            ? <><AmbiguousNotice>The encrypted response may already have been accepted.</AmbiguousNotice><StatusMessage tone="warning">Retry sends the exact same encrypted response. Do not edit the fields first.</StatusMessage><button className="primary-button full-button" onClick={() => { void submit(); }} type="button">Retry identical encrypted response</button></>
            : <><button className="primary-button full-button" disabled={!complete || state === "working"} type="submit">{state === "working" ? "Sending…" : "Send once"}</button><OperationNotice state={state} /></>}
        </form>
      : <div className="simple-form">
          <label className="field-block"><span>Second key</span><input autoComplete="off" onChange={(event) => { setFactor(event.currentTarget.value); }} placeholder="52-character key" spellCheck={false} value={factor} /></label>
          <button className="primary-button full-button" disabled={!factorValid || state === "working"} onClick={() => { void load(); }} type="button">Review request</button>
          {state === "waiting" ? <OperationNotice retry={() => { void load(); }} state={state} /> : <OperationNotice state={state} />}
        </div>}
  </div>;
}
