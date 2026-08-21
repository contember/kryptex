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
  return <div className="home-page">
    <div className="home-wordmark">Kryptex</div>
    <h1>Hand over a password without leaving it in someone&apos;s inbox.</h1>
    <p>Kryptex encrypts in your browser, gives you a link that expires, and never receives the readable secret. No account, nothing to install.</p>
    <div className="home-actions">
      <Link className="primary-button" reloadDocument to={gatePath("send")}>Send a secret</Link>
      <Link className="secondary-button" reloadDocument to={gatePath("request")}>Ask someone for a secret</Link>
    </div>
    <ol className="home-steps">
      <li>
        <strong>Write it here</strong>
        <p>Your browser encrypts the text. The service stores a sealed envelope and no key that opens it.</p>
      </li>
      <li>
        <strong>Share the link</strong>
        <p>Send the second key through a different channel, so one leaked message is not enough to open the secret.</p>
      </li>
      <li>
        <strong>It disappears</strong>
        <p>Once the allowed opens are used or the clock runs out, the stored copy is deleted.</p>
      </li>
    </ol>
    <div className="home-footer">
      <Link className="quiet-link" to="/security">What Kryptex protects — and where it stops</Link>
      <p className="notice notice--experimental">
        <strong>Experimental — not production-ready.</strong>
        <span>The protocol has had no independent cryptographic review and no tested production deployment. Use synthetic test data only.</span>
      </p>
    </div>
  </div>;
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

  return <div className="task-page task-page--narrow">
    <PageIntro title="One quick check">
      <p>This page only confirms that a person, not a script, is creating the transfer. It is deliberately kept apart: no secret, key, or draft ever reaches it.</p>
    </PageIntro>
    <div ref={container} />
    {state === "checking" ? <StatusMessage>Looking for a check you already passed…</StatusMessage> : null}
    {state === "loading" || state === "working" ? <StatusMessage>Waiting for the check…</StatusMessage> : null}
    {state === "retry" && token !== null
      ? <>
        <StatusMessage tone="warning">The result could not be confirmed.</StatusMessage>
        <button className="primary-button full-button" onClick={() => { setState("working"); setVerificationAttempt((attempt) => attempt + 1); }} type="button">Try the same check again</button>
      </>
      : null}
    {state === "failed"
      ? <>
        <StatusMessage tone="danger">The check is unavailable right now, so no form was opened. Nothing was created.</StatusMessage>
        <Link className="quiet-link" reloadDocument to="/">Back to the start</Link>
      </>
      : null}
  </div>;
}

export function SecurityPage() {
  return <div className="task-page">
    <PageIntro title="What Kryptex protects">
      <p>Plain answers to the questions worth asking before you trust a tool with a credential.</p>
    </PageIntro>
    <p className="notice notice--experimental">
      <strong>Experimental — not production-ready.</strong>
      <span>The protocol has had no independent cryptographic review and no tested production deployment. Use synthetic test data only.</span>
    </p>
    <InfoSection title="What stays in your browser">
      <p>The readable secret, your passphrase, the second key, and the encryption keys. The service receives an encrypted envelope and the derived permissions needed to store and release it.</p>
    </InfoSection>
    <InfoSection title="Why a second channel matters">
      <p>A link on its own is a bearer credential: whoever holds it can try to open the content. Sending the second key another way — a call, a different device, in person — means one intercepted message is not enough.</p>
    </InfoSection>
    <InfoSection title="What expiry can and cannot do">
      <p>Expiry deletes the stored copy, and revoking stops further opens. Neither can take back a secret that was already opened. Once someone reads it, protecting it is up to them.</p>
    </InfoSection>
    <InfoSection title="Where it stops">
      <p>Kryptex serves the code that does the encrypting. If that code were compromised, secrets used after that point could be exposed. The service can also see when transfers are created and released, just not what is in them.</p>
    </InfoSection>
    <Link className="quiet-link" to="/">Back to the start</Link>
  </div>;
}
