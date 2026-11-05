import { useEffect, useState } from "react";
import type { DeviceStatusResponse } from "@kryptex/contracts/api";
import type { DeviceLink } from "@kryptex/contracts/device-link";
import { DEVICE_PERMIT_TTL_SECONDS, DEVICE_QUOTA_PER_DAY } from "@kryptex/contracts/protocol";
import { ApiFailure, type KryptexClient } from "@kryptex/client";
import { useClient } from "../client-context";
import { consumeDeviceLink } from "../crypto-flow";
import { formatExactTime, formatHourStart, formatTimeLeft } from "../format";
import type { FragmentCapture } from "../fragment";
import { BurnAction, FieldHint, FragmentNotice, PageIntro, StatusMessage, StatusSheet, useNowSeconds } from "../ui";

type DeviceView =
  | { readonly kind: "loading" }
  | { readonly kind: "ready"; readonly checkedAt: number; readonly status: DeviceStatusResponse }
  | { readonly kind: "unavailable" }
  | { readonly kind: "rate_limited" }
  | { readonly kind: "unconfirmed" };

async function readDeviceStatus(client: KryptexClient, link: DeviceLink): Promise<DeviceView> {
  try {
    const status = await client.deviceStatus({ deviceLocator: link.deviceLocator, manageToken: link.manageToken });
    return { checkedAt: Math.floor(Date.now() / 1_000), kind: "ready", status };
  } catch (error) {
    if (error instanceof ApiFailure && error.code === "unavailable") return { kind: "unavailable" };
    if (error instanceof ApiFailure && error.code === "rate_limited") return { kind: "rate_limited" };
    return { kind: "unconfirmed" };
  }
}

/** `hourlyMints` runs oldest first and ends with the current UTC hour; rows are shown newest first. */
export function HourlyMints({ hourlyMints, checkedAt }: { readonly hourlyMints: readonly number[]; readonly checkedAt: number }) {
  const currentHourStart = Math.floor(checkedAt / 3_600) * 3_600;
  const rows = hourlyMints.map((count, index) => ({ count, hourStart: currentHourStart - (hourlyMints.length - 1 - index) * 3_600 })).reverse();
  const total = hourlyMints.reduce((sum, count) => sum + count, 0);
  return <section className="hourly-mints">
    <h2>Permits taken in the last 24 hours</h2>
    <FieldHint>These counts describe permits this machine took, not transfers anyone opened.</FieldHint>
    <table>
      <caption className="sr-only">Permits taken per hour, newest first</caption>
      <thead><tr><th scope="col">Hour starting</th><th scope="col">Permits</th></tr></thead>
      <tbody>
        {rows.map((row, index) => <tr key={row.hourStart}>
          <th scope="row">{formatHourStart(row.hourStart)}{index === 0 ? " (this hour)" : ""}</th>
          <td className="mono">{row.count}</td>
        </tr>)}
      </tbody>
      <tfoot><tr><th scope="row">Total</th><td className="mono">{total}</td></tr></tfoot>
    </table>
  </section>;
}

export function DeviceStatusView({ status, checkedAt, nowSeconds }: { readonly status: DeviceStatusResponse; readonly checkedAt: number; readonly nowSeconds: number }) {
  const active = status.state === "active";
  return <>
    <StatusSheet rows={[
      { label: "Status", value: active ? "Active" : "Revoked" },
      { label: active ? "Permission ends" : "Record kept until", value: <><strong>{formatTimeLeft(status.expiresAt, nowSeconds)}</strong><span className="mono">{formatExactTime(status.expiresAt)}</span></> },
      ...active ? [{ label: "Permits left", value: <span className="mono">{status.quotaRemaining} of {DEVICE_QUOTA_PER_DAY} in any 24 hours</span> }] : []
    ]} />
    {active
      ? <StatusMessage tone="success">This machine can create transfers until its permission ends or you revoke it.</StatusMessage>
      : <StatusMessage tone="danger">This machine&apos;s permission was revoked. It must pair again to create transfers.</StatusMessage>}
    <HourlyMints checkedAt={checkedAt} hourlyMints={status.hourlyMints} />
  </>;
}

export function DevicePage({ capture }: { readonly capture: FragmentCapture }) {
  const client = useClient();
  const [link] = useState(() => consumeDeviceLink(capture));
  const [view, setView] = useState<DeviceView>({ kind: "loading" });
  const [revoke, setRevoke] = useState<"idle" | "working" | "unconfirmed">("idle");
  const now = useNowSeconds();

  useEffect(() => {
    if (link === null) return;
    let cancelled = false;
    void readDeviceStatus(client, link).then((next) => { if (!cancelled) setView(next); });
    return () => { cancelled = true; };
  }, [client, link]);

  function refresh(): void {
    if (link === null) return;
    setView({ kind: "loading" });
    setRevoke("idle");
    void readDeviceStatus(client, link).then(setView);
  }

  function revokeDevice(): void {
    if (link === null) return;
    setRevoke("working");
    void client.revokeDevice({ deviceLocator: link.deviceLocator, manageToken: link.manageToken }).then(() => {
      refresh();
    }).catch((error: unknown) => {
      if (error instanceof ApiFailure && !error.ambiguous && error.code === "unavailable") { setRevoke("idle"); setView({ kind: "unavailable" }); return; }
      setRevoke("unconfirmed");
    });
  }

  return <div className="task-page task-page--narrow">
    <PageIntro title="Manage this machine">
      <p>This link controls one machine&apos;s standing permission to create transfers. Checking the status changes nothing.</p>
    </PageIntro>
    <FragmentNotice capture={capture} />

    {capture.hadFragment && link === null
      ? <StatusMessage tone="danger">This link is malformed or uses an unsupported version.</StatusMessage>
      : null}

    {link !== null && view.kind === "loading" ? <StatusMessage>Checking the status…</StatusMessage> : null}
    {view.kind === "ready" ? <DeviceStatusView checkedAt={view.checkedAt} nowSeconds={now} status={view.status} /> : null}
    {view.kind === "unavailable" ? <StatusMessage tone="warning">The record for this machine is unavailable.</StatusMessage> : null}
    {view.kind === "rate_limited" || view.kind === "unconfirmed"
      ? <div className="operation-notice">
        <strong>{view.kind === "rate_limited" ? "Too many attempts." : "Status could not be confirmed."}</strong>
        <p>{view.kind === "rate_limited" ? "Wait a moment, then check again." : "Checking again is safe and changes nothing."}</p>
        <button className="secondary-button" onClick={refresh} type="button">Check again</button>
      </div>
      : null}

    {view.kind === "ready" && view.status.state === "active"
      ? <section className="task-actions">
        <h2>Actions</h2>
        <div className="task-actions__row">
          <BurnAction
            confirmLabel="REVOKE"
            description={`The machine can no longer take permits to create transfers. Permits it already took stay valid for up to ${String(DEVICE_PERMIT_TTL_SECONDS / 60)} minutes. Transfers it already created are not affected. This cannot be undone.`}
            disabled={revoke === "working"}
            label="Revoke this machine's permission"
            onConfirm={revokeDevice}
            title="Revoke this machine's permission?"
          />
        </div>
      </section>
      : null}

    {revoke === "unconfirmed"
      ? <div className="operation-notice">
        <strong>The change was not confirmed.</strong>
        <p>The permission may already be revoked. Check the status before trying again.</p>
        <button className="secondary-button" onClick={refresh} type="button">Check the status</button>
      </div>
      : null}
  </div>;
}
