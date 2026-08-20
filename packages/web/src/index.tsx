import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { RouterProvider } from "react-router";

import { createAppRouter } from "./app";
import { captureAndScrubFragment, isSecretRoute } from "./fragment";
import "./styles.css";

const fragmentCapture = isSecretRoute(window.location.pathname)
  ? captureAndScrubFragment(window.location, window.history)
  : { canonicalPathname: null, fragmentBytes: null, hadFragment: false };

const root = document.getElementById("root");

if (root === null) {
  throw new Error("Kryptex root element is missing");
}

createRoot(root).render(
  <StrictMode>
    <RouterProvider router={createAppRouter(fragmentCapture)} />
  </StrictMode>
);
