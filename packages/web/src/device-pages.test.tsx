import { renderToStaticMarkup } from "react-dom/server";
import type { ReactNode } from "react";
import { RouterProvider, createMemoryRouter } from "react-router";
import { describe, expect, it } from "vitest";
import { parseDevicePairingClaimRequestJson, type DevicePairingClaimRequest } from "@kryptex/contracts/api";
import { decodeDeviceLink, encodeDeviceLink } from "@kryptex/contracts/device-link";
import { API_ROUTES } from "@kryptex/contracts/protocol";
import { KryptexClient } from "@kryptex/client";
import { decodeBase64Url, encodeBase64Url, randomBytes } from "@kryptex/crypto";
import { consumeDeviceLink } from "./crypto-flow";
import { formatFullDate } from "./format";
import { DeviceConfirmPage, GrantChoices, deviceClaimRequest, deviceManagementUrl, grantLifetimes } from "./pages/device-confirm-page";
import { DevicePage, DeviceStatusView } from "./pages/device-page";
import { DevicePairPage } from "./pages/static-pages";

const now = 1_800_000_000;

function render(element: ReactNode): string {
  return renderToStaticMarkup(<RouterProvider router={createMemoryRouter([{ path: "/", element }], { initialEntries: ["/"] })} />);
}

function occurrences(markup: string, needle: string): number {
  return markup.split(needle).length - 1;
}

describe("device pairing page", () => {
  it("never prefills the code from a fragment and wipes the copied bytes", () => {
    const fragmentBytes = new TextEncoder().encode("abcd-efgh");
    const markup = render(<DevicePairPage capture={{ canonicalPathname: "/pair/device", fragmentBytes, hadFragment: true }} />);
    expect(markup).toContain('value=""');
    expect(markup.toUpperCase()).not.toContain("ABCD");
    expect(markup).toContain("Type the code that your own terminal shows. Approving can give that terminal standing permission to create transfers.");
    expect(Array.from(fragmentBytes).every((byte) => byte === 0)).toBe(true);
  });
});

describe("device confirmation page", () => {
  it("offers only lifetimes up to the requested maximum", () => {
    expect(grantLifetimes(1)).toEqual([1]);
    expect(grantLifetimes(7)).toEqual([1, 7]);
    expect(grantLifetimes(90)).toEqual([1, 7, 30, 90]);
  });

  it("renders the choices with nothing preselected", () => {
    const markup = renderToStaticMarkup(<GrantChoices disabled={false} maxDays={7} nowSeconds={now} onChange={() => undefined} value={null} />);
    expect(markup).toContain("This transfer only");
    expect(occurrences(markup, "This machine until")).toBe(2);
    expect(markup).toContain(formatFullDate(now + 7 * 86_400));
    expect(markup).not.toContain(formatFullDate(now + 30 * 86_400));
    expect(markup).not.toContain("checked");
  });

  it("loads Turnstile nowhere and selects nothing before the status arrives", () => {
    const markup = render(<DeviceConfirmPage />);
    expect(markup).not.toContain("turnstile");
    expect(markup).not.toContain("checked");
  });

  it("claims a transfer without a management token", () => {
    expect(deviceClaimRequest("transfer")).toEqual({ scope: "transfer" });
  });

  it("sends a fresh 32-byte management token and builds a decodable device link", async () => {
    const request = deviceClaimRequest(30);
    if (request.scope !== "device") throw new Error("expected a device claim");
    expect(decodeBase64Url(request.manageToken).byteLength).toBe(32);
    const other = deviceClaimRequest(30);
    expect(other.scope === "device" ? other.manageToken : null).not.toBe(request.manageToken);

    const deviceLocator = encodeBase64Url(randomBytes(16));
    const sent: DevicePairingClaimRequest[] = [];
    const fetchStub: typeof fetch = (input, init) => {
      expect(input instanceof URL ? input.pathname : null).toBe(API_ROUTES.devicePairingClaim);
      const body = init?.body;
      if (typeof body !== "string") throw new Error("expected a JSON body");
      sent.push(parseDevicePairingClaimRequestJson(body));
      return Promise.resolve(new Response(`{"deviceExpiresAt":${now + 30 * 86_400},"deviceLocator":"${deviceLocator}","scope":"device"}`, { headers: { "Kryptex-Server-Time": String(now) } }));
    };
    const response = await new KryptexClient(fetchStub, "https://kryptex.example").claimDevicePairing(request);
    expect(sent).toEqual([{ days: 30, manageToken: request.manageToken, scope: "device" }]);
    if (response.scope !== "device") throw new Error("expected a device response");

    const url = deviceManagementUrl(response.deviceLocator, request.manageToken, "https://kryptex.example");
    expect(url.startsWith("https://kryptex.example/d#")).toBe(true);
    expect(decodeDeviceLink(url.slice(url.indexOf("#") + 1))).toEqual({ deviceLocator, manageToken: request.manageToken });
  });
});

describe("device management page", () => {
  it("wipes the fragment and keeps the token out of the markup", () => {
    const link = { deviceLocator: encodeBase64Url(randomBytes(16)), manageToken: encodeBase64Url(randomBytes(32)) };
    const encoded = encodeDeviceLink(link);
    const fragmentBytes = new TextEncoder().encode(encoded);
    const capture = { canonicalPathname: "/d", fragmentBytes, hadFragment: true };
    const markup = render(<DevicePage capture={capture} />);
    expect(Array.from(fragmentBytes).every((byte) => byte === 0)).toBe(true);
    expect(consumeDeviceLink(capture)).toEqual(link);
    expect(markup).toContain("Checking the status…");
    expect(markup).not.toContain(link.manageToken);
    expect(markup).not.toContain(link.deviceLocator);
    expect(markup).not.toContain(encoded);
  });

  it("reports a malformed link without calling it unavailable", () => {
    const markup = render(<DevicePage capture={{ canonicalPathname: "/d", fragmentBytes: new TextEncoder().encode("not-a-device-link"), hadFragment: true }} />);
    expect(markup).toContain("This link is malformed or uses an unsupported version.");
    expect(markup).not.toContain("Checking the status…");
  });

  it("renders state, expiry, quota, and 24 hourly counts as text", () => {
    const hourlyMints = Array.from({ length: 24 }, (_value, index) => index === 2 ? 3 : index === 23 ? 1 : 0);
    const markup = renderToStaticMarkup(<DeviceStatusView checkedAt={now} nowSeconds={now} status={{ expiresAt: now + 30 * 86_400, hourlyMints, quotaRemaining: 46, state: "active" }} />);
    expect(markup).toContain("Active");
    expect(markup).toContain("in 30 days");
    expect(markup).toContain("46 of 50 in any 24 hours");
    expect(markup).toContain("These counts describe permits this machine took, not transfers anyone opened.");
    expect(occurrences(markup, '<th scope="row">')).toBe(25);
    expect(markup).toMatch(/\(this hour\)<\/th><td class="mono">1<\/td>/u);
    expect(markup).toMatch(/Total<\/th><td class="mono">4<\/td>/u);
  });

  it("tells a revoked machine to pair again", () => {
    const markup = renderToStaticMarkup(<DeviceStatusView checkedAt={now} nowSeconds={now} status={{ expiresAt: now + 86_400, hourlyMints: Array.from({ length: 24 }, () => 0), quotaRemaining: 50, state: "revoked" }} />);
    expect(markup).toContain("Revoked");
    expect(markup).toContain("must pair again");
    expect(markup).not.toContain("Permits left");
  });
});
