import { renderToStaticMarkup } from "react-dom/server";
import type { ReactNode } from "react";
import { RouterProvider, createMemoryRouter } from "react-router";
import { describe, expect, it } from "vitest";
import { APP_ROUTES } from "./app";
import { RequestPage } from "./pages/request-page";
import { SendPage } from "./pages/send-page";
import { OperationNotice, ProtectionOptions, SecretField, ShareSlip } from "./ui";
import { creationPath, gatePath, parseCreationIntent } from "./verification";

function render(element: ReactNode): string {
  return renderToStaticMarkup(<RouterProvider router={createMemoryRouter([{ path: "/", element }], { initialEntries: ["/"] })} />);
}

describe("real route surface", () => {
  it("declares every product route", () => { expect(APP_ROUTES).toEqual(["/", "/send", "/request", "/s", "/m", "/r", "/i", "/gate", "/security"]); });
  it("composes before verification and keeps advanced options disclosed", () => { const send = render(<SendPage />); const request = render(<RequestPage />); expect(send).toContain("<textarea"); expect(send).toContain("Seal and create link"); expect(send).toContain("<summary>Protection and opens</summary>"); expect(send.indexOf("<details")).toBeLessThan(send.indexOf("Extra protection")); expect(request).toContain("Request title"); expect(request).toContain("Instructions"); expect(request).toContain("<summary>Field options</summary>"); expect(request).toContain("<summary>Protection</summary>"); expect(request).toContain("Instruction — label only"); expect(request).toContain("secondary-button"); expect(send).not.toContain("preview"); });
  it("states the expiry contract before the create action, outside any disclosure", () => { const send = render(<SendPage />); expect(send.indexOf("Delete after")).toBeLessThan(send.indexOf("<details")); expect(send).toContain("Deleted after 7 days"); expect(send).toContain("can be opened once"); expect(render(<RequestPage />)).toContain("Deleted after 7 days"); });
  it("routes creation through an isolated gate document", () => { expect(gatePath("send")).toBe("/gate?intent=send"); expect(gatePath("request")).toBe("/gate?intent=request"); expect(parseCreationIntent("?intent=send")).toBe("send"); expect(parseCreationIntent("?intent=request&extra=x")).toBeNull(); expect(creationPath("request")).toBe("/request"); });
  it("renders the recipient, separate factor, then optional management artifact", () => { const markup = render(<ShareSlip artifacts={[{ channel: "Recipient channel", id: "recipient", required: true, title: "Recipient link", value: "RECIPIENT-URL" }, { channel: "Separate channel", id: "factor", required: true, title: "Second key", value: "KEY-ONLY" }, { channel: "Local custody", id: "management", required: false, title: "Management link", value: "MANAGEMENT-URL" }]} onSaved={() => undefined} saved={{}} title="Secret" />); expect(markup.indexOf("RECIPIENT-URL")).toBeLessThan(markup.indexOf("KEY-ONLY")); expect(markup.indexOf("KEY-ONLY")).toBeLessThan(markup.indexOf("MANAGEMENT-URL")); expect(markup).toContain("Saved or not needed"); expect(markup).toContain("Copy"); expect(markup).toContain("0 of 3 parts stored"); expect(markup).toContain("Required"); expect(markup).not.toContain("not generated"); });
  it("keeps concealed values out of initial markup", () => { expect(renderToStaticMarkup(<SecretField label="API key" value="must-not-render" />)).not.toContain("must-not-render"); });
  it("uses generic failure copy", () => { expect(renderToStaticMarkup(<OperationNotice state="unknown" />)).toContain("could not confirm"); expect(renderToStaticMarkup(<OperationNotice state="unavailable" />)).not.toContain("Error:"); });
  it("states the limits of every protection mode", () => { const markup = renderToStaticMarkup(<ProtectionOptions onChange={() => undefined} value="second-key" />); expect(markup).toContain("same device or account may not be independent"); expect(markup).toContain("Argon2id raises guessing cost"); expect(markup).toContain("bearer credential"); });
});
