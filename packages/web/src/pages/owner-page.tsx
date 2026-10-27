import { useEffect, useState } from "react";
import type { RequestStatusResponse } from "@kryptex/contracts/api";
import type { RequestResponsePayload } from "@kryptex/contracts/payloads";
import { pickupRecoveryForStatus } from "@kryptex/client";
import { deriveRequestOwnerKeys, encodeBase64Url, equalBytes, openRequestResponse, parseKxr1Header, receiptDisplay } from "@kryptex/crypto";
import { useClient } from "../client-context";
import { artifactUrl, checkedResponseExpiry, consumeBundle, shortenedExpiryRequest, shouldPollRequestStatus } from "../crypto-flow";
import { describeRequestState, formatExactTime, formatTimeLeft, isSensitiveField } from "../format";
import type { FragmentCapture } from "../fragment";
import { AmbiguousNotice, BurnAction, FieldHint, FragmentNotice, OperationNotice, PageIntro, SecretField, ShareSlip, StatusMessage, StatusSheet, useNowSeconds, type OperationState } from "../ui";

type PickupRecovery = "none" | "checking" | "retry" | "lost";

const POLL_INTERVAL_MS = 10_000;
/** A few failed reads are a network blip; a run of them means the record is gone, so stop asking. */
const POLL_FAILURE_LIMIT = 5;

export function OwnerPage({ capture }: { readonly capture: FragmentCapture }) {
  const client = useClient();
  const [bundle] = useState(() => consumeBundle(capture, 4));
  const [status, setStatus] = useState<RequestStatusResponse | null>(null);
  const [state, setState] = useState<OperationState>("working");
  const [pickupRecovery, setPickupRecovery] = useState<PickupRecovery>("none");
  const [payload, setPayload] = useState<RequestResponsePayload | null>(null);
  const [fingerprint, setFingerprint] = useState<string | null>(null);
  const [replacement, setReplacement] = useState<string | null>(null);
  const [replacementSaved, setReplacementSaved] = useState(false);
  const [shortenUnavailable, setShortenUnavailable] = useState(false);
  const now = useNowSeconds();

  async function credentials() {
    if (bundle?.kind !== 4) throw new Error("Invalid pickup bundle");
    const keys = await deriveRequestOwnerKeys(bundle.ownerSeed);
    return { keys, locator: encodeBase64Url(bundle.requestLocator), ownerToken: encodeBase64Url(keys.ownerToken) };
  }

  async function readStatus(): Promise<RequestStatusResponse> {
    if (bundle?.kind !== 4) throw new Error("Invalid pickup bundle");
    const input = await credentials();
    const next = await client.requestStatus({ locator: input.locator, ownerToken: input.ownerToken });
    checkedResponseExpiry(bundle.serverExpiresAt, next.serverExpiresAt);
    return next;
  }

  async function refresh(): Promise<void> {
    setState("working");
    try {
      setStatus(await readStatus());
      setState("done");
    } catch {
      setState("unavailable");
    }
  }

  useEffect(() => {
    const timeout = window.setTimeout(() => { void (async () => {
      if (bundle?.kind !== 4) { setState("unavailable"); return; }
      try {
        const keys = await deriveRequestOwnerKeys(bundle.ownerSeed);
        const next = await client.requestStatus({ locator: encodeBase64Url(bundle.requestLocator), ownerToken: encodeBase64Url(keys.ownerToken) });
        checkedResponseExpiry(bundle.serverExpiresAt, next.serverExpiresAt);
        setStatus(next);
        setState("done");
      } catch {
        setState("unavailable");
      }
    })(); }, 0);
    return () => { window.clearTimeout(timeout); };
  }, [bundle, client]);

  const polling = shouldPollRequestStatus(state === "done", pickupRecovery !== "none", status?.state ?? null);

  useEffect(() => {
    if (!polling || bundle?.kind !== 4) return;
    let cancelled = false;
    let failures = 0;
    const timer = window.setInterval(() => {
      if (document.visibilityState !== "visible") return;
      void (async () => {
        try {
          const keys = await deriveRequestOwnerKeys(bundle.ownerSeed);
          const next = await client.requestStatus({ locator: encodeBase64Url(bundle.requestLocator), ownerToken: encodeBase64Url(keys.ownerToken) });
          checkedResponseExpiry(bundle.serverExpiresAt, next.serverExpiresAt);
          failures = 0;
          if (!cancelled) setStatus(next);
        } catch {
          failures += 1;
          if (failures >= POLL_FAILURE_LIMIT) window.clearInterval(timer);
        }
      })();
    }, POLL_INTERVAL_MS);
    return () => { cancelled = true; window.clearInterval(timer); };
  }, [bundle, client, polling]);

  async function reconcilePickup(): Promise<void> {
    setPickupRecovery("checking");
    setState("working");
    try {
      const next = await readStatus();
      setStatus(next);
      const decision = pickupRecoveryForStatus(next.state);
      if (decision === "retry") {
        setPickupRecovery("retry");
        setState("unknown");
      } else if (decision === "lost") {
        setPickupRecovery("lost");
        setState("done");
      } else {
        setPickupRecovery("none");
        setState("done");
      }
    } catch {
      setPickupRecovery("checking");
      setState("unknown");
    }
  }

  async function pickup(): Promise<void> {
    if (bundle?.kind !== 4 || status?.state !== "submitted") return;
    setState("working");
    setPickupRecovery("none");
    let dispatched = false;
    try {
      const input = await credentials();
      dispatched = true;
      const response = await client.pickupRequest({ locator: input.locator, ownerToken: input.ownerToken });
      const serverExpiresAt = checkedResponseExpiry(bundle.serverExpiresAt, response.metadata.serverExpiresAt);
      const header = parseKxr1Header(response.bytes);
      const opened = await openRequestResponse({ envelope: response.bytes, expectedClientNotAfter: header.clientNotAfter, hpkeIkm: input.keys.hpkeIkm, nowSeconds: Math.floor(Date.now() / 1_000), requestLocator: bundle.requestLocator, serverExpiresAt });
      if (encodeBase64Url(opened.receipt) !== response.metadata.receipt || !equalBytes(header.schemaDigest, opened.header.schemaDigest)) throw new Error("Receipt mismatch");
      setPayload(opened.payload);
      setFingerprint(await receiptDisplay(response.bytes));
      setStatus({ serverExpiresAt, state: "picked_up" });
      setState("done");
    } catch {
      if (dispatched) await reconcilePickup();
      else setState("unavailable");
    }
  }

  async function shorten(): Promise<void> {
    if (bundle?.kind !== 4 || status === null) return;
    setState("working");
    try {
      const input = await credentials();
      const requested = shortenedExpiryRequest(status.serverExpiresAt, Math.floor(Date.now() / 1_000));
      if (requested === null) { setShortenUnavailable(true); setState("done"); return; }
      setShortenUnavailable(false);
      const result = await client.shortenRequest({ locator: input.locator, ownerToken: input.ownerToken, serverExpiresAt: requested });
      const serverExpiresAt = checkedResponseExpiry(bundle.serverExpiresAt, result.serverExpiresAt);
      setReplacement(artifactUrl("/i", { ...bundle, serverExpiresAt }));
      await refresh();
    } catch {
      setState("unknown");
    }
  }

  async function revoke(): Promise<void> {
    setState("working");
    try {
      const input = await credentials();
      await client.revokeRequest({ locator: input.locator, ownerToken: input.ownerToken });
      await refresh();
    } catch {
      setState("unknown");
    }
  }

  if (payload !== null) {
    return <div className="task-page task-page--narrow">
      <PageIntro title={payload.schema.title}>
        <p>The answer was released once. Copy what you need now — reloading this page will not show it again.</p>
      </PageIntro>
      {payload.answers.map((answer) => {
        const field = payload.schema.fields.find((candidate) => candidate.id === answer.id);
        return <SecretField codeLike={field !== undefined && isSensitiveField(field.type)} key={answer.id} label={field?.label ?? answer.id} value={answer.value} />;
      })}
      <div className="fingerprint">
        <span>Receipt for this answer</span>
        <strong>{fingerprint}</strong>
        <p>Compare all 64 characters with the sender through a separate channel if it matters. A match only proves both browsers hold the same ciphertext bytes — it does not authenticate the writer, the plaintext, or the service.</p>
      </div>
    </div>;
  }

  const description = status === null ? null : describeRequestState(status.state);
  const pickupAction = status?.state !== "submitted"
    ? null
    : pickupRecovery === "retry"
      ? <AmbiguousNotice>
        <p>The status still says an answer is waiting. Only an explicit retry may release it.</p>
        <button className="primary-button" onClick={() => { void pickup(); }} type="button">Try opening it again</button>
      </AmbiguousNotice>
      : pickupRecovery === "checking"
        ? <AmbiguousNotice>
          <p>The answer may already have been released. Check the status before any retry.</p>
          <button className="primary-button" onClick={() => { void reconcilePickup(); }} type="button">Check the status</button>
        </AmbiguousNotice>
        : <button className="primary-button full-button" disabled={state === "working"} onClick={() => { void pickup(); }} type="button">{state === "working" ? "Opening…" : "Open the answer"}</button>;

  return <div className="task-page task-page--narrow">
    <PageIntro title="Your request">
      <p>This is your pickup link. Checking the status never releases the answer — only the button does, and only once.</p>
    </PageIntro>
    <FragmentNotice capture={capture} />

    {status === null || description === null
      ? null
      : <>
        <StatusSheet rows={[
          { label: "Status", value: description.label },
          { label: "Expires", value: <><strong>{formatTimeLeft(status.serverExpiresAt, now)}</strong><span className="mono">{formatExactTime(status.serverExpiresAt)}</span></> }
        ]} />
        {status.state === "picked_up" && pickupRecovery === "lost"
          ? <StatusMessage tone="danger">The answer was released, but this browser could not recover it. The service cannot release it a second time.</StatusMessage>
          : <StatusMessage tone={description.tone}>{description.detail}</StatusMessage>}
        {polling ? <FieldHint>This page rechecks the status every few seconds while it stays open. Checking never releases the answer.</FieldHint> : null}
      </>}

    {pickupAction}

    {status?.state === "waiting" || status?.state === "submitted"
      ? <section className="task-actions">
        <h2>Actions</h2>
        <div className="task-actions__row">
          <button className="secondary-button" disabled={shortenUnavailable || state === "working"} onClick={() => { void shorten(); }} type="button">Shorten to 15 minutes</button>
          <BurnAction
            confirmLabel="REVOKE"
            description="The write link stops working and any answer already submitted is destroyed unopened. This cannot be undone."
            disabled={state === "working"}
            label="Revoke now"
            onConfirm={() => { void revoke(); }}
            title="Revoke this request?"
          />
        </div>
        {shortenUnavailable
          ? <StatusMessage tone="warning">This request is already too close to deletion to shorten again.</StatusMessage>
          : <FieldHint>Shortening gives you a replacement pickup link — the current one stops matching.</FieldHint>}
      </section>
      : null}

    <OperationNotice retry={() => { void refresh(); }} state={pickupRecovery === "none" ? state : "idle"} />

    {replacement === null
      ? null
      : <ShareSlip
        artifacts={[{ channel: "Replace the copy you had saved. The previous pickup link no longer works.", id: "replacement", required: true, title: "Updated pickup link", value: replacement }]}
        onSaved={(_id, value) => { setReplacementSaved(value); }}
        saved={{ replacement: replacementSaved }}
        title="Expiry shortened"
      />}
  </div>;
}
