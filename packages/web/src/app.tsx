import { Link, Outlet, createBrowserRouter, useLocation } from "react-router";

import type { FragmentCapture } from "./fragment";
import { ManagementPage } from "./pages/management-page";
import { OwnerPage } from "./pages/owner-page";
import { RequestPage } from "./pages/request-page";
import { RetrievePage } from "./pages/retrieve-page";
import { SendPage } from "./pages/send-page";
import { GatePage, HomePage, SecurityPage } from "./pages/static-pages";
import { WriterPage } from "./pages/writer-page";

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
      { path: "send", element: <SendPage /> },
      { path: "request", element: <RequestPage /> },
      { path: "s", element: <RetrievePage capture={fragmentCapture} /> },
      { path: "m", element: <ManagementPage capture={fragmentCapture} /> },
      { path: "r", element: <WriterPage capture={fragmentCapture} /> },
      { path: "i", element: <OwnerPage capture={fragmentCapture} /> },
      { path: "gate", element: <GatePage /> },
      { path: "security", element: <SecurityPage /> }
    ]
  }]);
}

function RootLayout() {
  const location = useLocation();
  const flowName = FLOW_NAMES[location.pathname] ?? "Unknown route";
  if (location.pathname === "/") return <main><Outlet /></main>;
  return <div className="app-shell"><header className="masthead"><div className="masthead__inner"><Link className="wordmark" to="/" aria-label="Kryptex home">Kryptex</Link><span className="masthead__flow">{flowName}</span><span className="experimental-marker">Experimental</span></div></header><main><Outlet /></main></div>;
}

function RouteError() {
  return <section className="document document--narrow"><p className="eyebrow">Route unavailable</p><h1>This desk does not exist.</h1><p>The address is not part of the Kryptex preview.</p><Link className="button button--primary" to="/">Return to transfer desk</Link></section>;
}
