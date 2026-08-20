import { renderToStaticMarkup } from "react-dom/server";
import type { ReactNode } from "react";
import { RouterProvider, createMemoryRouter } from "react-router";
import { describe, expect, it } from "vitest";

import { APP_ROUTES } from "./app";
import { RequestPage } from "./pages/request-page";
import { SendPage } from "./pages/send-page";
import { PreviewAdapterProvider } from "./preview-context";
import { localPreviewAdapter } from "./preview-adapter";
import type { KryptexAdapter, PreviewRequestSchema } from "./preview-adapter";
import { OperationNotice, PreviewMark, SecretField, ShareSlip } from "./ui";
import { openIsolatedVerification } from "./verification";

function renderInRouter(element: ReactNode): string {
  const router = createMemoryRouter([{ path: "/", element }], { initialEntries: ["/"] });
  return renderToStaticMarkup(<RouterProvider router={router} />);
}

describe("simplified route surface", () => {
  it("declares every product route", () => {
    expect(APP_ROUTES).toEqual(["/", "/send", "/request", "/s", "/m", "/r", "/i", "/gate", "/security"]);
  });

  it("keeps gate opening, status check, and secret entry sequential", () => {
    const gated = renderInRouter(<SendPage />);
    const checking = renderInRouter(<SendPage initialGateOpened />);
    const permitted = renderInRouter(<SendPage initialPermit />);
    expect(gated).toContain("Verify to continue");
    expect(gated).not.toContain("<textarea");
    expect(gated).not.toContain("Check verification");
    expect(checking).toContain("Check verification");
    expect(checking).not.toContain("<textarea");
    expect(permitted).toContain("Expires after");
    expect(permitted).toContain("Create link");
    expect(permitted).toContain("<summary>Advanced</summary>");
    expect(permitted).not.toContain("lifecycle");
  });

  it("keeps the simple request builder behind the same sequential gate", () => {
    const gated = renderInRouter(<RequestPage />);
    const checking = renderInRouter(<RequestPage initialGateOpened />);
    const permitted = renderInRouter(<RequestPage initialPermit />);
    expect(gated).toContain("Verify to continue");
    expect(gated).not.toContain("Request title");
    expect(gated).not.toContain("Check verification");
    expect(checking).toContain("Check verification");
    expect(checking).not.toContain("Request title");
    expect(permitted).toContain("Request title");
    expect(permitted).toContain("Instructions");
    expect(permitted).toContain("What should they send?");
    expect(permitted).toContain("Add another item");
    expect(permitted).toContain("<summary>More options</summary>");
    expect(permitted).not.toContain(">instruction<");
  });

  it("opens the gate without an opener or referrer", () => {
    const calls: string[][] = [];
    openIsolatedVerification((url, target, features) => { calls.push([url, target, features]); });
    expect(calls).toEqual([["/gate", "_blank", "noopener,noreferrer"]]);
  });

  it("injects a preview adapter without browser storage or messaging", () => {
    const schema: PreviewRequestSchema = { fields: [{ help: "", id: 7, label: "Injected field", required: true, type: "secret" }], instructions: "Injected instructions", title: "Injected title" };
    const adapter: KryptexAdapter = {
      run(operation) { return Promise.resolve({ operation, outcome: "ok", simulated: true }); },
      readRequestSchema() { return schema; },
      rememberRequestSchema() { return undefined; }
    };
    const markup = renderInRouter(<PreviewAdapterProvider adapter={adapter}><RequestPage initialPermit /></PreviewAdapterProvider>);
    expect(markup).toContain("Injected title");
    expect(markup).toContain("Injected field");
  });

  it("keeps the exact edited request schema in current memory", () => {
    const schema: PreviewRequestSchema = { fields: [{ help: "Exact help", id: 91, label: "Exact label", required: true, type: "long" }], instructions: "Exact instructions", title: "Exact title" };
    localPreviewAdapter.rememberRequestSchema(schema);
    expect(localPreviewAdapter.readRequestSchema()).toEqual(schema);
  });
});

describe("safe states and accessibility", () => {
  it("marks only the share-slip seal as decorative and labels required acknowledgement", () => {
    const markup = renderInRouter(<ShareSlip artifacts={[{ channel: "Separate channel", id: "factor", required: true, title: "Second key" }]} onSaved={() => { return undefined; }} saved={{}} title="Secret" />);
    expect(markup).toContain("aria-hidden=\"true\"");
    expect(markup).toContain("Second key");
    expect(markup).toContain("Required");
    expect(markup).toContain("Saved");
  });

  it("keeps concealed values out of rendered and accessibility content", () => {
    const markup = renderToStaticMarkup(<SecretField label="API key" value="must-not-render" />);
    expect(markup).not.toContain("must-not-render");
    expect(markup).toContain("aria-hidden=\"true\"");
  });

  it("renders ambiguous and unavailable states without technical detail", () => {
    const unknown = renderToStaticMarkup(<OperationNotice state="unknown" />);
    const unavailable = renderToStaticMarkup(<OperationNotice state="unavailable" />);
    expect(unknown).toContain("could not confirm");
    expect(unavailable).toContain("Unavailable");
    expect(unavailable).toContain("expired, used, revoked, or incorrect");
  });

  it("always marks the app as an inert preview", () => {
    expect(renderToStaticMarkup(<PreviewMark />)).toContain("Crypto and API are not connected.");
  });
});
