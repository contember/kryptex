import { useEffect, useState } from "react";
import type { RequestStatusResponse } from "@kryptex/contracts/api";
import type { RequestResponsePayload } from "@kryptex/contracts/payloads";
import { deriveRequestOwnerKeys, encodeBase64Url, equalBytes, openRequestResponse, parseKxr1Header, receiptDisplay } from "@kryptex/crypto";
import { useClient } from "../client-context";
import { artifactUrl, checkedResponseExpiry, consumeBundle, pickupRecoveryForStatus, shortenedExpiryRequest } from "../crypto-flow";
import type { FragmentCapture } from "../fragment";
import { AmbiguousNotice, FragmentNotice, OperationNotice, PageIntro, SecretField, ShareSlip, StatusMessage, type OperationState } from "../ui";

type PickupRecovery = "none" | "checking" | "retry" | "lost";

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
    return <div className="task-page task-page--narrow"><PageIntro title={payload.schema.title}><p>Response opened once.</p></PageIntro>{payload.answers.map((answer) => { const field = payload.schema.fields.find((candidate) => candidate.id === answer.id); return <SecretField codeLike={field?.type === "secret"} key={answer.id} label={field?.label ?? answer.id} value={answer.value} />; })}<div className="fingerprint"><span>Local receipt — compare all 64 hexadecimal digits through an independent channel</span><strong>{fingerprint}</strong><p>A match only means both browsers hold the same ciphertext bytes. It does not authenticate the writer, plaintext, or service behavior.</p></div></div>;
  }

  const statusNotice = status?.state === "waiting"
    ? <StatusMessage>Waiting for a response.</StatusMessage>
    : status?.state === "picked_up" && pickupRecovery === "lost"
      ? <StatusMessage tone="danger">The response was released, but this browser could not recover it. The service cannot release it again.</StatusMessage>
      : status !== null && status.state !== "submitted"
        ? <StatusMessage tone="warning">This request is {status.state}.</StatusMessage>
        : null;
  const pickupAction = status?.state !== "submitted"
    ? null
    : pickupRecovery === "retry"
      ? <AmbiguousNotice>Status still says submitted. Only an explicit retry may consume the response.<button onClick={() => { void pickup(); }} type="button">Retry consuming pickup</button></AmbiguousNotice>
      : pickupRecovery === "checking"
        ? <AmbiguousNotice>Pickup may have completed. Check status before any retry.<button onClick={() => { void reconcilePickup(); }} type="button">Check pickup status</button></AmbiguousNotice>
        : <button className="primary-button full-button" onClick={() => { void pickup(); }} type="button">Open response once</button>;

  return <div className="task-page task-page--narrow"><PageIntro title="Response"><p>Status checks do not consume the response.</p></PageIntro><FragmentNotice capture={capture} />{status === null ? null : <div className="status-sheet"><div><span>Status</span><strong>{status.state}</strong></div><div><span>Expires</span><strong>{new Date(status.serverExpiresAt * 1_000).toLocaleString()}</strong></div></div>}{pickupAction}{statusNotice}{status?.state === "waiting" || status?.state === "submitted" ? <details className="advanced"><summary>More</summary><div className="task-actions"><button disabled={shortenUnavailable} onClick={() => { void shorten(); }} type="button">Shorten to 15 minutes</button><button className="danger-button" onClick={() => { void revoke(); }} type="button">Revoke</button>{shortenUnavailable ? <StatusMessage tone="warning">This request is too close to expiry to shorten again.</StatusMessage> : null}</div></details> : null}<OperationNotice retry={() => { void refresh(); }} state={pickupRecovery === "none" ? state : "idle"} />{replacement === null ? null : <ShareSlip artifacts={[{ channel: "Replace the old local copy.", id: "replacement", required: true, title: "Updated pickup link", value: replacement }]} onSaved={(_id, value) => { setReplacementSaved(value); }} saved={{ replacement: replacementSaved }} title="Expiry shortened" />}</div>;
}
