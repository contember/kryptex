import { useRef, useState } from "react";

import type { FragmentCapture } from "../fragment";
import { usePreviewOperation } from "../preview-hooks";
import { reconcilePickup } from "../preview-transitions";
import { ConfirmDialog, FragmentNotice, OperationNotice, PageIntro, PreviewMark, SecretField, ShareSlip, StatusMessage, type OperationState } from "../ui";

type OwnerStatus = "submitted" | "opened" | "revoked" | "consumed";

export function OwnerPage({ capture }: { readonly capture: FragmentCapture }) {
  const operation = usePreviewOperation();
  const schema = operation.adapter.readRequestSchema();
  const [status, setStatus] = useState<OwnerStatus>("submitted");
  const [state, setState] = useState<OperationState>("idle");
  const [unknownPickup, setUnknownPickup] = useState(false);
  const [openDialog, setOpenDialog] = useState(false);
  const [revokeDialog, setRevokeDialog] = useState(false);
  const [retryPickup, setRetryPickup] = useState(false);
  const [replacement, setReplacement] = useState(false);
  const [saved, setSaved] = useState<Readonly<Record<string, boolean>>>({});
  const openTriggerRef = useRef<HTMLButtonElement>(null);
  const revokeTriggerRef = useRef<HTMLButtonElement>(null);

  async function open(): Promise<void> {
    setState("working");
    setUnknownPickup(false);
    setRetryPickup(false);
    try {
      const result = await operation.run("pickup");
      if (result.outcome === "unavailable") setState("unavailable");
      else { setStatus("opened"); setOpenDialog(false); setState("done"); }
    } catch {
      setOpenDialog(false);
      setUnknownPickup(true);
      setState("unknown");
    }
  }

  async function checkPickupStatus(): Promise<void> {
    setState("working");
    setUnknownPickup(false);
    const result = await reconcilePickup(operation.adapter);
    if (result === "retry") { setRetryPickup(true); setState("idle"); }
    else if (result === "opened") { setStatus("consumed"); setState("done"); }
    else if (result === "waiting") setState("waiting");
    else setState("unavailable");
  }

  async function revoke(): Promise<void> {
    setState("working");
    setUnknownPickup(false);
    try {
      await operation.run("revoke");
      setStatus("revoked");
      setRevokeDialog(false);
      setState("done");
    } catch {
      setState("unknown");
    }
  }

  async function shorten(): Promise<void> {
    setState("working");
    setUnknownPickup(false);
    try { await operation.run("shorten"); setReplacement(true); setState("done"); }
    catch { setState("unknown"); }
  }

  return <div className="task-page task-page--narrow">
    <PageIntro title="Response"><p>{status === "submitted" ? "A response is ready to open once." : status === "opened" ? "Response opened." : status === "consumed" ? "Response already opened." : "Request revoked."}</p></PageIntro>
    <PreviewMark />
    <FragmentNotice capture={capture} />
    {status === "opened"
      ? <div className="result-sheet">
          <StatusMessage tone="success">Opened once</StatusMessage>
          {schema.fields.map((field) => <SecretField codeLike={field.type === "secret"} key={field.id} label={field.label} value={field.type === "secret" ? "DEMO_ONLY_NOT_A_SECRET" : "demo response"} />)}
          <div className="fingerprint"><span>Receipt</span><strong>DEMO FINGERPRINT — NOT COMPUTED</strong></div>
        </div>
      : status === "revoked"
        ? <StatusMessage tone="danger">No response can be opened from this request.</StatusMessage>
        : status === "consumed"
          ? <StatusMessage tone="danger">The status check found that the response was already opened. It cannot be recovered here.</StatusMessage>
          : <>
              {retryPickup
                ? <><StatusMessage tone="warning">The response is still available. Trying again sends another consuming pickup request.</StatusMessage><button className="primary-button full-button" onClick={() => { void open(); }} type="button">Try opening again</button></>
                : <button className="primary-button full-button" onClick={() => { setOpenDialog(true); }} ref={openTriggerRef} type="button">Open once</button>}
              <ConfirmDialog confirmLabel="OPEN" description="If the response is lost during opening, the service may not be able to return it again." onCancel={() => { setOpenDialog(false); }} onConfirm={() => { void open(); }} open={openDialog} restoreFocus={openTriggerRef} title="Open response?" />
              <details className="advanced">
                <summary>More</summary>
                <div className="task-actions">
                  <button onClick={() => { void shorten(); }} type="button">Shorten expiry</button>
                  <button className="danger-button" onClick={() => { setRevokeDialog(true); }} ref={revokeTriggerRef} type="button">Revoke</button>
                </div>
              </details>
              <ConfirmDialog confirmLabel="REVOKE" description="The response link will stop working. Already opened content cannot be taken back." onCancel={() => { setRevokeDialog(false); }} onConfirm={() => { void revoke(); }} open={revokeDialog} restoreFocus={revokeTriggerRef} title="Revoke this response?" />
            </>}
    {unknownPickup || state === "waiting" ? <OperationNotice retry={() => { void checkPickupStatus(); }} state={state} /> : <OperationNotice state={state} />}
    {replacement ? <ShareSlip artifacts={[{ channel: "Replace your old local copy.", id: "replacement", required: false, route: "/i", title: "Updated pickup link" }]} onSaved={(id, value) => { setSaved({ [id]: value }); }} saved={saved} title="Expiry shortened" /> : null}
  </div>;
}
