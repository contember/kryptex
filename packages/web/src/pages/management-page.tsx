import { useEffect, useState } from "react";
import type { SendStatusResponse } from "@kryptex/contracts/api";
import { deriveSendManagementKeys, encodeBase64Url } from "@kryptex/crypto";
import { useClient } from "../client-context";
import { artifactUrl, checkedResponseExpiry, consumeBundle, shortenedExpiryRequest } from "../crypto-flow";
import { describeSendState, formatExactTime, formatTimeLeft } from "../format";
import type { FragmentCapture } from "../fragment";
import { BurnAction, FieldHint, FragmentNotice, OperationNotice, PageIntro, ShareSlip, StatusMessage, StatusSheet, useNowSeconds, type OperationState } from "../ui";

export function ManagementPage({ capture }: { readonly capture: FragmentCapture }) {
  const client = useClient();
  const [bundle] = useState(() => consumeBundle(capture, 2));
  const [status, setStatus] = useState<SendStatusResponse | null>(null);
  const [state, setState] = useState<OperationState>("working");
  const [replacement, setReplacement] = useState<string | null>(null);
  const [replacementSaved, setReplacementSaved] = useState(false);
  const [shortenUnavailable, setShortenUnavailable] = useState(false);
  const [localExpiryUnconfirmed, setLocalExpiryUnconfirmed] = useState(false);
  const now = useNowSeconds();

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

  const description = status === null ? null : describeSendState(status.state);

  return <div className="task-page task-page--narrow">
    <PageIntro title="Manage this secret">
      <p>This is your own copy of the transfer. Checking the status never uses up an open.</p>
    </PageIntro>
    <FragmentNotice capture={capture} />

    {status === null || description === null
      ? null
      : <>
        <StatusSheet rows={status.state === "active"
          ? [
            { label: "Status", value: description.label },
            { label: "Opens left", value: <span className="mono">{status.remainingRetrievals}</span> },
            { label: "Expires", value: <><strong>{formatTimeLeft(status.serverExpiresAt, now)}</strong><span className="mono">{formatExactTime(status.serverExpiresAt)}</span></> }
          ]
          : [
            { label: "Status", value: description.label },
            { label: "Expires", value: <><strong>{formatTimeLeft(status.serverExpiresAt, now)}</strong><span className="mono">{formatExactTime(status.serverExpiresAt)}</span></> }
          ]} />
        <StatusMessage tone={description.tone}>{description.detail}</StatusMessage>
        <FieldHint>An open is one released copy of the ciphertext. It does not tell you whether a person read it.</FieldHint>
      </>}

    {status?.state === "active"
      ? <section className="task-actions">
        <h2>Actions</h2>
        <div className="task-actions__row">
          <button className="secondary-button" disabled={shortenUnavailable || state === "working"} onClick={() => { void shorten(); }} type="button">Shorten to 15 minutes</button>
          <BurnAction
            confirmLabel="REVOKE"
            description="The recipient will no longer be able to open this secret. Anything already released stays with whoever opened it. This cannot be undone."
            disabled={state === "working"}
            label="Revoke now"
            onConfirm={() => { void revoke(); }}
            title="Revoke this secret?"
          />
        </div>
        {shortenUnavailable
          ? <StatusMessage tone="warning">This secret is already too close to deletion to shorten again.</StatusMessage>
          : <FieldHint>Shortening gives you a replacement management link — the current one stops matching.</FieldHint>}
      </section>
      : null}

    {localExpiryUnconfirmed
      ? <StatusMessage tone="warning">By this link&apos;s own clock the secret has expired, but the service did not answer, so that could not be confirmed.</StatusMessage>
      : <OperationNotice retry={() => { void refresh(); }} state={state} />}

    {replacement === null
      ? null
      : <ShareSlip
        artifacts={[{ channel: "Replace the copy you had saved. The previous management link no longer works.", id: "replacement", required: true, title: "Updated management link", value: replacement }]}
        onSaved={(_id, value) => { setReplacementSaved(value); }}
        saved={{ replacement: replacementSaved }}
        title="Expiry shortened"
      />}
  </div>;
}
