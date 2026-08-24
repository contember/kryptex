import { useEffect, useState, type ReactNode } from "react";
import { Link, Outlet, createBrowserRouter, useLocation } from "react-router";

import { ApiFailure } from "./api-client";
import { useClient } from "./client-context";
import type { FragmentCapture } from "./fragment";
import { ManagementPage } from "./pages/management-page";
import { OwnerPage } from "./pages/owner-page";
import { RequestPage } from "./pages/request-page";
import { RetrievePage } from "./pages/retrieve-page";
import { SendPage } from "./pages/send-page";
import { GatePage, HomePage, SecurityPage } from "./pages/static-pages";
import { WriterPage } from "./pages/writer-page";
import { PageIntro } from "./ui";
import { gatePath, type CreationIntent } from "./verification";

export const APP_ROUTES: readonly string[] = ["/", "/send", "/request", "/s", "/m", "/r", "/i", "/gate", "/security"];

const FLOW_NAMES: Readonly<Record<string, string>> = {
  "/": "Home",
  "/send": "Send a secret",
  "/request": "Request a secret",
  "/s": "Open a secret",
  "/m": "Manage a secret",
  "/r": "Answer a request",
  "/i": "Your request",
  "/gate": "Quick check",
  "/security": "Security"
};

export function createAppRouter(fragmentCapture: FragmentCapture) {
  return createBrowserRouter([{
    element: <RootLayout />,
    errorElement: <RouteError />,
    children: [
      { index: true, element: <HomePage /> },
      { path: "send", element: <CreationPermitGuard intent="send"><SendPage /></CreationPermitGuard> },
      { path: "request", element: <CreationPermitGuard intent="request"><RequestPage /></CreationPermitGuard> },
      { path: "s", element: <RetrievePage capture={fragmentCapture} /> },
      { path: "m", element: <ManagementPage capture={fragmentCapture} /> },
      { path: "r", element: <WriterPage capture={fragmentCapture} /> },
      { path: "i", element: <OwnerPage capture={fragmentCapture} /> },
      { path: "gate", element: <GatePage /> },
      { path: "security", element: <SecurityPage /> }
    ]
  }]);
}

function CreationPermitGuard({ children, intent }: { readonly children: ReactNode; readonly intent: CreationIntent }) {
  const client = useClient();
  const [state, setState] = useState<"checking" | "ready" | "unavailable">("checking");

  useEffect(() => {
    let cancelled = false;
    void client.permitStatus().then(() => {
      if (!cancelled) setState("ready");
    }).catch((error: unknown) => {
      if (cancelled) return;
      if (error instanceof ApiFailure && error.code === "creation_permit_required") {
        window.location.replace(gatePath(intent));
        return;
      }
      setState("unavailable");
    });
    return () => { cancelled = true; };
  }, [client, intent]);

  if (state === "ready") return children;
  return <div className="task-page task-page--narrow">
    <PageIntro step="Quick check" title={state === "checking" ? "Opening the form…" : "The check is unavailable"}>
      <p>{state === "checking" ? "The form opens as soon as the check is confirmed." : "Reload the page to try again. No form was opened and nothing was created."}</p>
    </PageIntro>
  </div>;
}

function RootLayout() {
  const location = useLocation();
  const flowName = FLOW_NAMES[location.pathname] ?? "Unknown route";
  if (location.pathname === "/") return <main><Outlet /></main>;
  return <div className="app-shell">
    <header className="masthead">
      <div className="masthead__inner">
        <Link aria-label="Kryptex home" className="wordmark" to="/">Kryptex</Link>
        <span className="masthead__flow">{flowName}</span>
        <Link className="masthead__security" to="/security">Security</Link>
      </div>
    </header>
    <main><Outlet /></main>
  </div>;
}

function RouteError() {
  return <div className="task-page task-page--narrow">
    <PageIntro step="Nothing here" title="This address is not part of Kryptex">
      <p>Check that you copied the whole link. Messengers often cut off everything after the <span className="mono">#</span>, which is the part that opens a secret.</p>
    </PageIntro>
    <Link className="primary-button" to="/">Back to the start</Link>
  </div>;
}
