import { useRef, useState } from "react";

import type { FragmentCapture } from "../fragment";
import { usePreviewOperation } from "../preview-hooks";
import { ConfirmDialog, FragmentNotice, OperationNotice, PageIntro, PreviewMark, ShareSlip, StatusMessage, type OperationState } from "../ui";

export function ManagementPage({ capture }: { readonly capture: FragmentCapture }) {
  const [status, setStatus] = useState<"active" | "revoked">("active");
  const [expiry, setExpiry] = useState("30 minutes");
  const [replacement, setReplacement] = useState(false);
  const [saved, setSaved] = useState<Readonly<Record<string, boolean>>>({});
  const [dialogOpen, setDialogOpen] = useState(false);
  const [state, setState] = useState<OperationState>("idle");
  const triggerRef = useRef<HTMLButtonElement>(null);
  const operation = usePreviewOperation();
  async function shorten(): Promise<void> { setState("working"); try { await operation.run("shorten"); setReplacement(true); setState("done"); } catch { setState("unknown"); } }
  async function revoke(): Promise<void> { setState("working"); try { await operation.run("revoke"); setStatus("revoked"); setDialogOpen(false); setState("done"); } catch { setState("unknown"); } }
  return <div className="task-page task-page--narrow"><PageIntro title="Manage link"><p>See whether the link is active, shorten it, or revoke it.</p></PageIntro><PreviewMark /><FragmentNotice capture={capture} /><div className="status-sheet"><div><span>Status</span><strong className={status === "active" ? "success-text" : "danger-text"}>{status === "active" ? "Active" : "Revoked"}</strong></div><div><span>Retrievals left</span><strong>{status === "active" ? "1" : "—"}</strong></div><div><span>Expires</span><strong>in 1 hour</strong></div></div>{status === "revoked" ? <StatusMessage tone="danger">This link can no longer be opened.</StatusMessage> : <div className="task-actions"><details><summary>Shorten expiry</summary><div><fieldset className="compact-options"><legend>New expiry</legend>{["15 minutes", "30 minutes"].map((value) => <label key={value}><input checked={expiry === value} name="expiry" onChange={() => { setExpiry(value); }} type="radio" /><span>{value}</span></label>)}</fieldset><button onClick={() => { void shorten(); }} type="button">Shorten</button></div></details><button className="danger-button" onClick={() => { setDialogOpen(true); }} ref={triggerRef} type="button">Revoke</button><ConfirmDialog confirmLabel="REVOKE" description="The link will stop working. Already opened content cannot be taken back." onCancel={() => { setDialogOpen(false); }} onConfirm={() => { void revoke(); }} open={dialogOpen} restoreFocus={triggerRef} title="Revoke this link?" /></div>}<OperationNotice state={state} />{replacement ? <ShareSlip artifacts={[{ channel: "Replace your old local copy.", id: "replacement", required: false, route: "/m", title: "Updated management link" }]} onSaved={(id, value) => { setSaved({ [id]: value }); }} saved={saved} title="Expiry shortened" /> : null}</div>;
}
