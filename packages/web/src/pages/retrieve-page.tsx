import { useState } from "react";

import type { FragmentCapture } from "../fragment";
import { usePreviewOperation } from "../preview-hooks";
import { AmbiguousNotice, FragmentNotice, OperationNotice, PageIntro, PreviewMark, SecretField, StatusMessage, type OperationState } from "../ui";
import { isValidCrockfordFactor } from "../validation";

export function RetrievePage({ capture }: { readonly capture: FragmentCapture }) {
  const [factor, setFactor] = useState("");
  const [opened, setOpened] = useState(false);
  const [state, setState] = useState<OperationState>("idle");
  const operation = usePreviewOperation();
  const factorValid = isValidCrockfordFactor(factor);

  async function open(): Promise<void> {
    setState("working");
    try {
      const result = await operation.run("retrieve");
      if (result.outcome === "unavailable") setState("unavailable");
      else if (result.outcome === "waiting" || result.outcome === "pending") setState("waiting");
      else { setOpened(true); setState("done"); }
    } catch {
      setState("unknown");
    }
  }

  return <div className="task-page task-page--narrow">
    <PageIntro title="Open secret"><p>Opening uses one available retrieval.</p></PageIntro>
    <PreviewMark />
    <FragmentNotice capture={capture} />
    {opened
      ? <div className="result-sheet">
          <StatusMessage tone="success">Opened · no retrievals remain</StatusMessage>
          <SecretField label="API key" value="DEMO_ONLY_NOT_A_SECRET" />
          <p className="fine-print">The sender cannot take back content you already opened.</p>
        </div>
      : <div className="simple-form">
          <label className="field-block">
            <span>Second key</span>
            <input autoComplete="off" onChange={(event) => { setFactor(event.currentTarget.value); }} placeholder="52-character key" spellCheck={false} value={factor} />
            <small>{factorValid ? "Key format complete" : "Enter the complete key sent separately"}</small>
          </label>
          {state === "unknown"
            ? <>
                <AmbiguousNotice>The first opening may already have used one available retrieval.</AmbiguousNotice>
                <StatusMessage tone="warning">Trying again sends another consuming request and may use another available opening.</StatusMessage>
                <button className="primary-button full-button" onClick={() => { void open(); }} type="button">Try opening again</button>
              </>
            : <>
                <button className="primary-button full-button" disabled={!factorValid || state === "working"} onClick={() => { void open(); }} type="button">{state === "working" ? "Opening…" : "Open once"}</button>
                <OperationNotice state={state} />
              </>}
        </div>}
  </div>;
}
