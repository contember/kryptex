import { useEffect, useState, type ReactNode } from "react";
import type { SendStatusResponse } from "@kryptex/contracts/api";
import { deriveSendManagementKeys, encodeBase64Url } from "@kryptex/crypto";
import { useClient } from "../client-context";
import { artifactUrl, checkedResponseExpiry, consumeBundle, shortenedExpiryRequest } from "../crypto-flow";
import { describeSendState, formatExactTime, formatFailedAttempts, formatOpened, formatTimeLeft } from "../format";
import type { FragmentCapture } from "../fragment";
import { BurnAction, FieldHint, FragmentNotice, LinkProblem, OperationNotice, PageIntro, ShareSlip, StatusMessage, StatusSheet, useNowSeconds, type OperationState } from "../ui";

interface StatusRow {
  readonly label: string;
  readonly value: ReactNode;
}

/** Release times and wrong-token attempts are the only access facts Kryptex holds; it never records who opened a secret. */
function statusRows(status: SendStatusResponse, stateLabel: string, nowSeconds: number): readonly StatusRow[] {
  return [
    { label: "Status", value: stateLabel },
    ...status.state === "active"
      ? [{ label: "Opens left", value: <span className="mono">{status.remainingRetrievals}</span> }]
      : [],
    {
      label: "Opened",
      value: <>
        <strong>{formatOpened(status.releasedAt.length)}</strong>
        {status.releasedAt.map((releasedAt, index) => <span className="mono" key={`${String(releasedAt)}-${String(index)}`}>{formatExactTime(releasedAt)}</span>)}
      </>
    },
    ...status.failedAccessAttempts > 0
      ? [{ label: "Failed attempts", value: <span className="mono">{formatFailedAttempts(status.failedAccessAttempts)}</span> }]
      : [],
    {
      label: "Expires",
      value: <><strong>{formatTimeLeft(status.serverExpiresAt, nowSeconds)}</strong><span className="mono">{formatExactTime(status.serverExpiresAt)}</span></>
    }
  ];
}

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

  if (bundle?.kind !== 2) return <LinkProblem capture={capture} flow="management link" />;

  const description = status === null ? null : describeSendState(status.state);
  const rows = status === null || description === null ? null : statusRows(status, description.label, now);

  return <div className="task-page task-page--narrow">
    <PageIntro title="Manage this secret">
      <p>This page is for you, the sender. Looking at it does not use up an open.</p>
    </PageIntro>
    <FragmentNotice capture={capture} />

    {status === null || description === null
      ? null
      : <>
        <StatusSheet rows={rows ?? []} />
        <StatusMessage tone={description.tone}>{description.detail}</StatusMessage>
        {status.failedAccessAttempts > 0
          ? <StatusMessage tone="warning">Someone tried to open this secret with a wrong link or key. If that was not the person you sent it to, revoke it.</StatusMessage>
          : null}
        <FieldHint>An open means the encrypted secret was sent to a browser. It does not mean someone read it. Kryptex does not record who opened it.</FieldHint>
      </>}

    {status?.state === "active"
      ? <section className="task-actions">
        <h2>Actions</h2>
        <div className="task-actions__row">
          <button className="secondary-button" disabled={shortenUnavailable || state === "working"} onClick={() => { void shorten(); }} type="button">Shorten to 15 minutes</button>
          <BurnAction
            confirmLabel="REVOKE"
            description="The link stops working right away. Anyone who already opened it keeps what they saw. This cannot be undone."
            disabled={state === "working"}
            label="Revoke now"
            onConfirm={() => { void revoke(); }}
            title="Revoke this secret?"
          />
        </div>
        {shortenUnavailable
          ? <StatusMessage tone="warning">This secret ends in a moment, so it cannot be shortened.</StatusMessage>
          : <FieldHint>After shortening you get an updated management link with the new end time. Save it in place of the old one.</FieldHint>}
      </section>
      : null}

    {localExpiryUnconfirmed
      ? <StatusMessage tone="warning">This link says it has expired. The server record is unavailable, so the service could not confirm that state.</StatusMessage>
      : <OperationNotice retry={() => { void refresh(); }} state={state} />}

    {replacement === null
      ? null
      : <ShareSlip
        artifacts={[{ channel: "Save this in place of the management link you kept. It knows the new end time.", id: "replacement", required: true, title: "Updated management link", value: replacement }]}
        onSaved={(_id, value) => { setReplacementSaved(value); }}
        saved={{ replacement: replacementSaved }}
        title="Time shortened"
      />}
  </div>;
}
