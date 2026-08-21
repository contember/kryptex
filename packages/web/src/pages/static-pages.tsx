import { useEffect, useRef, useState } from "react";
import { Link, useLocation } from "react-router";
import { ApiFailure } from "../api-client";
import { useClient } from "../client-context";
import { InfoSection, PageIntro, StatusMessage } from "../ui";
import { creationPath, gatePath, parseCreationIntent } from "../verification";

const DEVELOPMENT_SITE_KEY = "1x00000000000000000000AA";

export function resolveTurnstileSiteKey(configured: string | undefined, production: boolean): string | null {
  return configured === undefined || configured.length === 0 ? (production ? null : DEVELOPMENT_SITE_KEY) : configured;
}

declare global {
  interface ImportMetaEnv {
    PROD: boolean;
    readonly VITE_TURNSTILE_SITE_KEY?: string;
  }
  interface ImportMeta { readonly env: ImportMetaEnv; }
  interface Window { readonly turnstile?: { render(container: HTMLElement, options: { readonly action: "create_permit"; readonly callback: (token: string) => void; readonly sitekey: string }): string; }; }
}

export function HomePage() {
  return <div className="home-page"><div className="home-wordmark">Kryptex</div><h1>Send sensitive information without giving the service the readable secret.</h1><p>Encrypted in the browser. Shared by link. No account needed.</p><div className="home-actions"><Link className="primary-button" reloadDocument to={gatePath("send")}>Send secret</Link><Link className="secondary-button" reloadDocument to={gatePath("request")}>Request secret</Link></div><Link className="quiet-link" to="/security">Security</Link><p className="home-experimental">Experimental — not production-ready</p></div>;
}

export function GatePage() {
  const client = useClient();
  const location = useLocation();
  const container = useRef<HTMLDivElement>(null);
  const [requestId] = useState(() => crypto.randomUUID().toLowerCase());
  const [token, setToken] = useState<string | null>(null);
  const [verificationAttempt, setVerificationAttempt] = useState(0);
  const intent = parseCreationIntent(location.search);
  const [state, setState] = useState<"checking" | "loading" | "working" | "retry" | "failed">(intent === null ? "failed" : "checking");
  const configured = import.meta.env.VITE_TURNSTILE_SITE_KEY;
  const siteKey = resolveTurnstileSiteKey(configured, import.meta.env.PROD);
  const destination = intent === null ? null : creationPath(intent);

  useEffect(() => {
    if (destination === null) return;
    let cancelled = false;
    void client.permitStatus().then(() => {
      if (!cancelled) window.location.replace(destination);
    }).catch((error: unknown) => {
      if (cancelled) return;
      if (error instanceof ApiFailure && error.code === "creation_permit_required") {
        setState(siteKey === null ? "failed" : "loading");
        return;
      }
      setState("failed");
    });
    return () => { cancelled = true; };
  }, [client, destination, siteKey]);

  useEffect(() => {
    if (destination === null || token === null || verificationAttempt === 0) return;
    let cancelled = false;
    void client.createPermit({ requestId, turnstileResponse: token }).then(() => {
      if (!cancelled) window.location.replace(destination);
    }).catch((error: unknown) => {
      if (!cancelled) setState(error instanceof ApiFailure && error.ambiguous ? "retry" : "failed");
    });
    return () => { cancelled = true; };
  }, [client, destination, requestId, token, verificationAttempt]);

  useEffect(() => {
    if (siteKey === null || state !== "loading") return;
    const activeSiteKey = siteKey;
    let cancelled = false;
    function render(): void {
      if (cancelled || container.current === null || window.turnstile === undefined) return;
      window.turnstile.render(container.current, { action: "create_permit", callback(responseToken) { setState("working"); setToken(responseToken); setVerificationAttempt((attempt) => attempt + 1); }, sitekey: activeSiteKey });
    }
    if (window.turnstile !== undefined) { render(); return () => { cancelled = true; }; }
    const script = document.createElement("script");
    script.src = "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit";
    script.async = true; script.defer = true;
    script.addEventListener("load", render);
    script.addEventListener("error", () => { if (!cancelled) setState("failed"); });
    document.head.appendChild(script);
    return () => { cancelled = true; script.removeEventListener("load", render); script.remove(); };
  }, [siteKey, state]);

  return <div className="task-page task-page--narrow"><PageIntro title="Confirm you are human"><p>This isolated page receives no secret or key material. The secret form opens only after verification.</p></PageIntro><div ref={container} />{state === "checking" ? <StatusMessage>Checking for an existing verification…</StatusMessage> : null}{state === "loading" || state === "working" ? <StatusMessage>Waiting for verification…</StatusMessage> : null}{state === "retry" && token !== null ? <><StatusMessage tone="warning">The result could not be confirmed.</StatusMessage><button className="primary-button full-button" onClick={() => { setState("working"); setVerificationAttempt((attempt) => attempt + 1); }} type="button">Retry the same verification</button></> : null}{state === "failed" ? <><StatusMessage tone="danger">Verification is unavailable. No permit was created.</StatusMessage><Link className="quiet-link" reloadDocument to="/">Return home</Link></> : null}</div>;
}

export function SecurityPage() {
  return <div className="task-page"><PageIntro title="Security"><p>Kryptex is experimental and not production-ready.</p></PageIntro><InfoSection title="What stays in your browser"><p>Readable secrets, passphrases, second keys, and encryption keys. The server receives encrypted envelopes and derived capabilities.</p></InfoSection><InfoSection title="Channel separation"><p>A separate second key reduces damage if one channel is compromised. Never send it together with its link.</p></InfoSection><InfoSection title="Limits"><p>Compromised first-party browser code can read content while you use it. A recipient can retain anything they open.</p></InfoSection><Link className="quiet-link" to="/">Back</Link></div>;
}
