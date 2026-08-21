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
import { gatePath, type CreationIntent } from "./verification";

export const APP_ROUTES: readonly string[] = ["/", "/send", "/request", "/s", "/m", "/r", "/i", "/gate", "/security"];

const FLOW_NAMES: Readonly<Record<string, string>> = {
  "/": "Home",
  "/send": "Send secret",
  "/request": "Request secret",
  "/s": "Open secret",
  "/m": "Manage link",
  "/r": "Answer request",
  "/i": "Open response",
  "/gate": "Verification",
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
  return <div className="task-page task-page--narrow"><p className="eyebrow">Creation verification</p><h1>{state === "checking" ? "Checking verification…" : "Verification is unavailable"}</h1><p>{state === "checking" ? "The secret form will open after the permit is confirmed." : "Reload the page to try again. No secret form was opened."}</p></div>;
}

function RootLayout() {
  const location = useLocation();
  const flowName = FLOW_NAMES[location.pathname] ?? "Unknown route";
  if (location.pathname === "/") return <main><Outlet /></main>;
  return <div className="app-shell"><header className="masthead"><div className="masthead__inner"><Link className="wordmark" to="/" aria-label="Kryptex home">Kryptex</Link><span className="masthead__flow">{flowName}</span><span className="experimental-marker">Experimental — not production-ready</span></div></header><main><Outlet /></main></div>;
}

function RouteError() {
  return <section className="document document--narrow"><p className="eyebrow">Route unavailable</p><h1>This desk does not exist.</h1><p>The address is not part of Kryptex.</p><Link className="button button--primary" to="/">Return to transfer desk</Link></section>;
}
