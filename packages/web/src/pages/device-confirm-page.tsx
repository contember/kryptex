import { useEffect, useState } from "react";
import type { DevicePairingClaimRequest, DevicePairingClaimStatusResponse } from "@kryptex/contracts/api";
import { encodeDeviceLink } from "@kryptex/contracts/device-link";
import { DEVICE_GRANT_DAYS, DEVICE_QUOTA_PER_DAY, type DeviceGrantDays } from "@kryptex/contracts/protocol";
import { encodeBase64Url, randomBytes } from "@kryptex/crypto";
import { ApiFailure, type KryptexClient } from "@kryptex/client";
import { useClient } from "../client-context";
import { formatDays, formatFullDate } from "../format";
import { ExpiryNote, FieldHint, NavigationGuard, PageIntro, ShareSlip, StatusMessage, useNowSeconds } from "../ui";

export type GrantChoice = "transfer" | DeviceGrantDays;

export function grantLifetimes(maxDays: DeviceGrantDays): readonly DeviceGrantDays[] {
  return DEVICE_GRANT_DAYS.filter((days) => days <= maxDays);
}

/** The management token is drawn in this Turnstile-free document and kept for an identical retry. */
export function deviceClaimRequest(choice: GrantChoice): DevicePairingClaimRequest {
  return choice === "transfer"
    ? { scope: "transfer" }
    : { days: choice, manageToken: encodeBase64Url(randomBytes(32)), scope: "device" };
}

export function deviceManagementUrl(deviceLocator: string, manageToken: string, origin = window.location.origin): string {
  return `${new URL("/d", origin).href}#${encodeDeviceLink({ deviceLocator, manageToken })}`;
}

type ConfirmView =
  | { readonly kind: "loading" }
  | { readonly kind: "status_failed" }
  | { readonly kind: "unavailable" }
  | { readonly kind: "choosing"; readonly status: DevicePairingClaimStatusResponse }
  | { readonly kind: "claiming"; readonly request: DevicePairingClaimRequest; readonly status: DevicePairingClaimStatusResponse }
  | { readonly kind: "retry"; readonly rateLimited: boolean; readonly request: DevicePairingClaimRequest; readonly status: DevicePairingClaimStatusResponse }
  | { readonly kind: "transfer" }
  | { readonly kind: "device"; readonly expiresAt: number; readonly link: string };

async function readClaimStatus(client: KryptexClient): Promise<ConfirmView> {
  try {
    return { kind: "choosing", status: await client.devicePairingClaimStatus() };
  } catch (error) {
    return error instanceof ApiFailure && error.code === "unavailable" ? { kind: "unavailable" } : { kind: "status_failed" };
  }
}

export function GrantChoices({ maxDays, nowSeconds, value, onChange, disabled }: { readonly maxDays: DeviceGrantDays; readonly nowSeconds: number; readonly value: GrantChoice | null; readonly onChange: (value: GrantChoice) => void; readonly disabled: boolean }) {
  return <fieldset className="option-list" disabled={disabled}>
    <legend>What may this terminal do?</legend>
    <label>
      <input checked={value === "transfer"} name="grant" onChange={() => { onChange("transfer"); }} type="radio" />
      <span>
        <strong>This transfer only</strong>
        <small>The terminal can create one transfer.</small>
      </span>
    </label>
    {grantLifetimes(maxDays).map((days) => <label key={days}>
      <input checked={value === days} name="grant" onChange={() => { onChange(days); }} type="radio" />
      <span>
        <strong>This machine until {formatFullDate(nowSeconds + days * 86_400)}</strong>
        <small>{formatDays(days)}. The terminal can create up to {DEVICE_QUOTA_PER_DAY} transfers in any 24 hours, until then or until you revoke it.</small>
      </span>
    </label>)}
  </fieldset>;
}

export function DeviceConfirmPage() {
  const client = useClient();
  const [view, setView] = useState<ConfirmView>({ kind: "loading" });
  const [choice, setChoice] = useState<GrantChoice | null>(null);
  const [saved, setSaved] = useState(false);
  const now = useNowSeconds();

  useEffect(() => {
    let cancelled = false;
    void readClaimStatus(client).then((next) => { if (!cancelled) setView(next); });
    return () => { cancelled = true; };
  }, [client]);

  function reloadStatus(): void {
    setView({ kind: "loading" });
    void readClaimStatus(client).then(setView);
  }

  function claim(request: DevicePairingClaimRequest, status: DevicePairingClaimStatusResponse): void {
    setView({ kind: "claiming", request, status });
    void client.claimDevicePairing(request).then((response) => {
      if (request.scope === "transfer" && response.scope === "transfer") { setView({ kind: "transfer" }); return; }
      if (request.scope === "device" && response.scope === "device") {
        setView({ expiresAt: response.deviceExpiresAt, kind: "device", link: deviceManagementUrl(response.deviceLocator, request.manageToken) });
        return;
      }
      setView({ kind: "unavailable" });
    }).catch((error: unknown) => {
      // Only a definite refusal ends the attempt; anything else keeps the identical request for a safe retry.
      if (error instanceof ApiFailure && !error.ambiguous && error.code !== "rate_limited") setView({ kind: "unavailable" });
      else setView({ kind: "retry", rateLimited: error instanceof ApiFailure && error.code === "rate_limited", request, status });
    });
  }

  const pendingDeviceClaim = (view.kind === "claiming" || view.kind === "retry") && view.request.scope === "device";
  const guard = <NavigationGuard
    description={pendingDeviceClaim ? "Leaving now permanently loses the management link this page is waiting for." : "Kryptex keeps no copy of the management link. Once this page closes, nothing can bring it back."}
    title={pendingDeviceClaim ? "Keep confirming this approval?" : "Save the management link first?"}
    when={pendingDeviceClaim || (view.kind === "device" && !saved)}
  />;

  if (view.kind === "transfer") {
    return <div className="task-page task-page--narrow">
      <PageIntro title="Approved">
        <p>The terminal can create one transfer.</p>
      </PageIntro>
      <StatusMessage tone="success">Approved for one transfer. Return to your terminal.</StatusMessage>
    </div>;
  }

  if (view.kind === "device") {
    return <div className="task-page task-page--narrow">
      <PageIntro title="Keep the management link">
        <p>This machine can now create transfers. The link below is the only way to see its activity or revoke its permission from a browser.</p>
      </PageIntro>
      <ShareSlip
        artifacts={[{ channel: "Keep this link to see how many transfers this machine started and to revoke its permission.", id: "management", required: false, savedLabel: "Management link saved or intentionally discarded", title: "Device management link", value: view.link }]}
        note={<ExpiryNote expiresAt={view.expiresAt} label="Permission ends" />}
        onSaved={(_id, value) => { setSaved(value); }}
        saved={{ management: saved }}
        title="This machine is approved"
      >
        <StatusMessage tone="success">Approved. Return to your terminal.</StatusMessage>
      </ShareSlip>
      {guard}
    </div>;
  }

  if (view.kind === "loading") {
    return <div className="task-page task-page--narrow">
      <PageIntro title="Approve a terminal"><p>Checking the approval…</p></PageIntro>
    </div>;
  }

  if (view.kind === "status_failed") {
    return <div className="task-page task-page--narrow">
      <PageIntro title="Approve a terminal"><p>Nothing was approved yet.</p></PageIntro>
      <StatusMessage tone="warning">The approval could not be checked.</StatusMessage>
      <button className="secondary-button" onClick={reloadStatus} type="button">Check again</button>
    </div>;
  }

  if (view.kind === "unavailable") {
    return <div className="task-page task-page--narrow">
      <PageIntro title="Approve a terminal"><p>Nothing more can be approved on this page.</p></PageIntro>
      <StatusMessage tone="danger">This code is wrong, expired, or already used. Your terminal can start a new pairing.</StatusMessage>
      <FieldHint>If this page already showed a management link, it cannot show it again.</FieldHint>
    </div>;
  }

  const { status } = view;
  const busy = view.kind === "claiming";
  const locked = view.kind !== "choosing";
  return <div className="task-page task-page--narrow">
    <PageIntro title="Approve a terminal">
      <p>Your terminal asked for permission for up to {formatDays(status.maxDays)}. You can give it less, never more.</p>
    </PageIntro>
    <GrantChoices disabled={locked} maxDays={status.maxDays} nowSeconds={now} onChange={setChoice} value={choice} />
    {view.kind === "retry"
      ? <>
        <StatusMessage tone="warning">{view.rateLimited ? "Too many attempts. Wait a moment, then try the same approval again." : "The approval could not be confirmed. Trying again sends the same choice."}</StatusMessage>
        <button className="primary-button full-button" onClick={() => { claim(view.request, status); }} type="button">Try the same approval again</button>
      </>
      : <button className="primary-button full-button" disabled={choice === null || busy} onClick={() => { if (choice !== null) claim(deviceClaimRequest(choice), status); }} type="button">
        {busy ? "Approving…" : "Approve"}
      </button>}
    {guard}
  </div>;
}
