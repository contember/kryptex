import { useEffect, useState } from "react";
import type { SendStatusResponse } from "@kryptex/contracts/api";
import { deriveSendManagementKeys, encodeBase64Url } from "@kryptex/crypto";
import { useClient } from "../client-context";
import { artifactUrl, checkedResponseExpiry, consumeBundle, shortenedExpiryRequest } from "../crypto-flow";
import type { FragmentCapture } from "../fragment";
import { FragmentNotice, OperationNotice, PageIntro, ShareSlip, StatusMessage, type OperationState } from "../ui";

export function ManagementPage({ capture }: { readonly capture: FragmentCapture }) {
  const client = useClient();
  const [bundle] = useState(() => consumeBundle(capture, 2));
  const [status, setStatus] = useState<SendStatusResponse | null>(null);
  const [state, setState] = useState<OperationState>("working");
  const [replacement, setReplacement] = useState<string | null>(null);
  const [replacementSaved, setReplacementSaved] = useState(false);
  const [shortenUnavailable, setShortenUnavailable] = useState(false);
  const [localExpiryUnconfirmed, setLocalExpiryUnconfirmed] = useState(false);

  async function refresh(): Promise<void> {
    if (bundle?.kind !== 2) { setState("unavailable"); return; }
    try { const keys = await deriveSendManagementKeys(bundle.manageSeed); const next = await client.sendStatus({ locator: encodeBase64Url(bundle.locator), manageToken: encodeBase64Url(keys.manageToken) }); checkedResponseExpiry(bundle.serverExpiresAt, next.serverExpiresAt); setStatus(next); setLocalExpiryUnconfirmed(false); setState("done"); }
    catch { setLocalExpiryUnconfirmed(Math.floor(Date.now() / 1_000) >= bundle.serverExpiresAt); setState("unavailable"); }
  }
  useEffect(() => {
    const timeout = window.setTimeout(() => { void (async () => {
      if (bundle?.kind !== 2) { setState("unavailable"); return; }
      try { const keys = await deriveSendManagementKeys(bundle.manageSeed); const next = await client.sendStatus({ locator: encodeBase64Url(bundle.locator), manageToken: encodeBase64Url(keys.manageToken) }); checkedResponseExpiry(bundle.serverExpiresAt, next.serverExpiresAt); setStatus(next); setLocalExpiryUnconfirmed(false); setState("done"); }
      catch { setLocalExpiryUnconfirmed(Math.floor(Date.now() / 1_000) >= bundle.serverExpiresAt); setState("unavailable"); }
    })(); }, 0);
    return () => { window.clearTimeout(timeout); };
  }, [bundle, client]);

  async function shorten(): Promise<void> {
    if (bundle?.kind !== 2 || status === null) return;
    setState("working");
    try {
      const keys = await deriveSendManagementKeys(bundle.manageSeed);
      const requested = shortenedExpiryRequest(status.serverExpiresAt, Math.floor(Date.now() / 1_000));
      if (requested === null) { setShortenUnavailable(true); setState("done"); return; }
      setShortenUnavailable(false);
      const result = await client.shortenSend({ locator: encodeBase64Url(bundle.locator), manageToken: encodeBase64Url(keys.manageToken), serverExpiresAt: requested });
      const serverExpiresAt = checkedResponseExpiry(bundle.serverExpiresAt, result.serverExpiresAt);
      setReplacement(artifactUrl("/m", { ...bundle, serverExpiresAt })); await refresh();
    } catch { setState("unknown"); }
  }
  async function revoke(): Promise<void> {
    if (bundle?.kind !== 2) return;
    setState("working");
    try { const keys = await deriveSendManagementKeys(bundle.manageSeed); await client.revokeSend({ locator: encodeBase64Url(bundle.locator), manageToken: encodeBase64Url(keys.manageToken) }); await refresh(); }
    catch { setState("unknown"); }
  }
  return <div className="task-page task-page--narrow"><PageIntro title="Manage link"><p>Status checks do not consume a release.</p></PageIntro><FragmentNotice capture={capture} />{status === null ? null : <div className="status-sheet"><div><span>Status</span><strong>{status.state}</strong></div><div><span>Retrievals left</span><strong>{status.remainingRetrievals}</strong></div><div><span>Expires</span><strong>{new Date(status.serverExpiresAt * 1_000).toLocaleString()}</strong></div></div>}{status?.state === "active" ? <details className="advanced"><summary>More</summary><div className="task-actions"><button disabled={shortenUnavailable} onClick={() => { void shorten(); }} type="button">Shorten to 15 minutes</button><button className="danger-button" onClick={() => { void revoke(); }} type="button">Revoke</button>{shortenUnavailable ? <StatusMessage tone="warning">This link is too close to expiry to shorten again.</StatusMessage> : null}</div></details> : status !== null ? <StatusMessage tone="warning">This link is {status.state}.</StatusMessage> : null}{localExpiryUnconfirmed ? <StatusMessage tone="warning">This link says it has expired. The server record is unavailable, so the service could not confirm that state.</StatusMessage> : <OperationNotice retry={() => { void refresh(); }} state={state} />}{replacement === null ? null : <ShareSlip artifacts={[{ channel: "Replace the old local copy.", id: "replacement", required: true, title: "Updated management link", value: replacement }]} onSaved={(_id, value) => { setReplacementSaved(value); }} saved={{ replacement: replacementSaved }} title="Expiry shortened" />}</div>;
}
