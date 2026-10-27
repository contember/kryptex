import { useEffect, useEffectEvent, useRef, useState, type RefObject } from "react";
import { Link, useLocation } from "react-router";
import { normalizeUserCodeInput } from "@kryptex/contracts/api";
import { ApiFailure } from "@kryptex/client";
import { useClient } from "../client-context";
import type { FragmentCapture } from "../fragment";
import { FieldHint, InfoSection, PageIntro, StatusMessage } from "../ui";
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

/** Loads Turnstile into `container` while `active`; the script never loads into a document that holds secret material. */
function useTurnstileWidget(
  container: RefObject<HTMLDivElement | null>,
  siteKey: string | null,
  active: boolean,
  onToken: (token: string) => void,
  onFailure: () => void
): void {
  const tokenReceived = useEffectEvent(onToken);
  const loadFailed = useEffectEvent(onFailure);
  useEffect(() => {
    if (siteKey === null || !active) return;
    const activeSiteKey = siteKey;
    let cancelled = false;
    function render(): void {
      if (cancelled || container.current === null || window.turnstile === undefined) return;
      window.turnstile.render(container.current, { action: "create_permit", callback(responseToken) { tokenReceived(responseToken); }, sitekey: activeSiteKey });
    }
    if (window.turnstile !== undefined) { render(); return () => { cancelled = true; }; }
    const script = document.createElement("script");
    script.src = "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit";
    script.async = true; script.defer = true;
    script.addEventListener("load", render);
    script.addEventListener("error", () => { if (!cancelled) loadFailed(); });
    document.head.appendChild(script);
    return () => { cancelled = true; script.removeEventListener("load", render); script.remove(); };
  }, [container, siteKey, active]);
}

export function HomePage() {
  return <div className="home-page">
    <div className="home-brand">
      <span className="home-wordmark">Kryptex</span>
      <span className="home-tagline">Simple, yet secure secret sharing</span>
    </div>
    <h1>Hand over a password without leaving it in someone&apos;s inbox.</h1>
    <p>Write the secret, share the link, watch access close. Kryptex encrypts in your browser and never receives the readable secret — no account, nothing to install.</p>
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
        <strong>Access closes</strong>
        <p>Once the allowed opens are used or the clock runs out, the service releases nothing else and starts deleting the stored ciphertext.</p>
      </li>
    </ol>
    <div className="home-footer">
      <Link className="quiet-link" to="/security">What Kryptex protects — and where it stops</Link>
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

  useTurnstileWidget(container, siteKey, state === "loading", (responseToken) => {
    setState("working"); setToken(responseToken); setVerificationAttempt((attempt) => attempt + 1);
  }, () => { setState("failed"); });

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

function initialUserCode(capture: FragmentCapture): string {
  const fragment = capture.fragmentBytes;
  if (fragment === null) return "";
  try {
    return normalizeUserCodeInput(new TextDecoder("utf-8", { fatal: true }).decode(fragment)) ?? "";
  } catch {
    return "";
  } finally {
    fragment.fill(0);
  }
}

export function PairPage({ capture }: { readonly capture: FragmentCapture }) {
  const client = useClient();
  const container = useRef<HTMLDivElement>(null);
  const [requestId] = useState(() => crypto.randomUUID().toLowerCase());
  const [code, setCode] = useState(() => initialUserCode(capture));
  const [token, setToken] = useState<string | null>(null);
  const siteKey = resolveTurnstileSiteKey(import.meta.env.VITE_TURNSTILE_SITE_KEY, import.meta.env.PROD);
  const [state, setState] = useState<"ready" | "working" | "retry" | "approved" | "unavailable" | "failed">(siteKey === null ? "failed" : "ready");
  const userCode = normalizeUserCodeInput(code);

  useTurnstileWidget(container, siteKey, state !== "failed" && state !== "approved", setToken, () => { setState("failed"); });

  function approve(): void {
    if (userCode === null || token === null) return;
    setState("working");
    void client.approvePairing({ requestId, turnstileResponse: token, userCode }).then(() => {
      setState("approved");
    }).catch((error: unknown) => {
      if (error instanceof ApiFailure && error.ambiguous) setState("retry");
      else setState(error instanceof ApiFailure && error.code === "unavailable" ? "unavailable" : "failed");
    });
  }

  if (state === "approved") {
    return <div className="task-page task-page--narrow">
      <PageIntro title="Approved">
        <p>Return to your terminal. It can now create one transfer.</p>
      </PageIntro>
    </div>;
  }

  return <div className="task-page task-page--narrow">
    <PageIntro title="Approve a terminal">
      <p>A command-line client asked for permission to create one transfer. Approve only a code that your own terminal shows. Approving gives that terminal one permission to create a transfer.</p>
    </PageIntro>
    <div className="field-block">
      <label><span>Code shown in your terminal</span><input autoComplete="off" className="mono" onChange={(event) => { setCode(event.currentTarget.value); }} placeholder="XXXX-XXXX" spellCheck={false} type="text" value={code} /></label>
      {code.length > 0 && userCode === null ? <FieldHint>A code is 8 characters, usually written as two groups of four.</FieldHint> : null}
    </div>
    <div ref={container} />
    {state === "ready" || state === "retry"
      ? <button className="primary-button full-button" disabled={userCode === null || token === null} onClick={approve} type="button">
        {state === "retry" ? "Try the same approval again" : "Approve this terminal"}
      </button>
      : null}
    {state === "ready" && token === null ? <StatusMessage>Waiting for the check…</StatusMessage> : null}
    {state === "working" ? <StatusMessage>Approving…</StatusMessage> : null}
    {state === "retry" ? <StatusMessage tone="warning">The approval could not be confirmed.</StatusMessage> : null}
    {state === "unavailable"
      ? <StatusMessage tone="danger">This code is wrong, expired, or already used. Your terminal can start a new pairing.</StatusMessage>
      : null}
    {state === "failed"
      ? <StatusMessage tone="danger">The check is unavailable right now. Nothing was approved.</StatusMessage>
      : null}
  </div>;
}

export function SecurityPage() {
  return <div className="task-page">
    <PageIntro title="What Kryptex protects">
      <p>Plain answers to the questions worth asking before you trust a tool with a credential.</p>
    </PageIntro>
    <InfoSection title="What stays in your browser">
      <p>The readable secret, your passphrase, the second key, and the encryption keys. The service receives an encrypted envelope and the derived permissions needed to store and release it.</p>
    </InfoSection>
    <InfoSection title="Why a second channel matters">
      <p>A link on its own is a bearer credential: whoever holds it can try to open the content. Sending the second key another way — a call, a different device, in person — means one intercepted message is not enough.</p>
    </InfoSection>
    <InfoSection title="What expiry can and cannot do">
      <p>Expiry and revocation stop further releases and start deleting the active stored copy. Failed deletion is retried, and provider backups may persist. Neither can take back a secret that was already opened.</p>
    </InfoSection>
    <InfoSection title="Where it stops">
      <p>Kryptex serves the code that does the encrypting. If that code were compromised, secrets used after that point could be exposed. The service can also see when transfers are created and released, just not what is in them.</p>
    </InfoSection>
    <TechnicalDescription />
    <Link className="quiet-link" to="/">Back to the start</Link>
  </div>;
}

function TechnicalDescription() {
  return <div className="tech-spec">
    <header className="tech-spec__head">
      <p className="eyebrow">Technical description</p>
      <h2>How a secret is encrypted, transferred, and stored</h2>
      <p>The exact steps for protocol version 1, in the order they happen. All cryptography runs in the browser through WebCrypto, except Argon2id, which runs in WebAssembly. The byte-level format is frozen in the protocol specification in the source repository and is covered by checked-in test vectors.</p>
    </header>

    <InfoSection title="1. Key material is generated in the browser">
      <ul>
        <li>The sender&apos;s browser draws a 32-byte <strong>send seed</strong> <code>S</code> and a 32-byte <strong>management seed</strong> <code>M</code> from <code>crypto.getRandomValues</code>.</li>
        <li>A 32-byte <strong>factor</strong> <code>F</code> depends on the chosen protection:
          <ul>
            <li><em>Link only</em> — 32 zero bytes.</li>
            <li><em>Second key</em> — 16 random bytes, expanded to 32 bytes with HKDF-SHA-256. They are shown to the sender as 26 Crockford Base32 characters and never enter the link.</li>
            <li><em>Passphrase</em> — Argon2id (version 0x13, 64&nbsp;MiB memory, 3 passes, 1 lane) over the UTF-8 passphrase with a fresh 16-byte random salt, 32-byte output.</li>
          </ul>
        </li>
        <li>HKDF-SHA-256 with domain-separated labels (<code>kryptex/v1/send/…</code>) derives everything else:
          <ul>
            <li><code>locator</code> (16 bytes) from <code>S</code> alone — the server-side name of the transfer.</li>
            <li><code>contentKey</code> (32 bytes) and <code>retrieveToken</code> (32 bytes) from <code>S&nbsp;||&nbsp;F</code> — so the wrong factor yields a wrong key and a wrong token.</li>
            <li><code>manageToken</code> (32 bytes) from <code>M</code>.</li>
          </ul>
        </li>
      </ul>
      <p>The content key is used once and discarded. It is never serialized, stored, or transmitted.</p>
    </InfoSection>

    <InfoSection title="2. The secret is padded and encrypted">
      <ul>
        <li>The secret is serialized as canonical JSON (RFC 8785): <code>{"{"}&quot;kind&quot;:&quot;text&quot;,&quot;text&quot;:…{"}"}</code> or a <code>fields</code> list.</li>
        <li>A 4-byte length prefix, the payload, and cryptographically random padding are packed into the smallest fitting bucket of 4&nbsp;KiB, 16&nbsp;KiB, 64&nbsp;KiB, 256&nbsp;KiB, or 1&nbsp;MiB. The service and the network see only the bucket size, not the exact length.</li>
        <li>The bucket is encrypted with <strong>AES-256-GCM</strong> under <code>contentKey</code>, a fresh random 12-byte nonce, and a 16-byte authentication tag.</li>
        <li>A 62-byte clear header — magic <code>KXE1</code>, suite, mode, factor mode, client expiry, allowed opens, and the nonce — is bound to the ciphertext as additional authenticated data. Changing any header byte makes decryption fail.</li>
      </ul>
      <p>The result is one <strong>sealed envelope</strong>: header plus ciphertext plus tag.</p>
    </InfoSection>

    <InfoSection title="3. The envelope is transferred, the keys are not">
      <ul>
        <li>The browser sends one <code>POST /api/v1/sends</code> over HTTPS carrying the envelope (base64url), the <code>locator</code>, the <code>retrieveToken</code>, the <code>manageToken</code>, the chosen lifetime, the allowed number of opens, and a random attempt ID for safe retries.</li>
        <li>It does <em>not</em> send the seed <code>S</code>, the factor, the passphrase, the second key, or the content key. Nothing the server receives can decrypt the envelope.</li>
        <li>The recipient link is <code>https://…/s#&lt;bundle&gt;</code>. The bundle after <code>#</code> holds <code>S</code>, the factor mode, the Argon2id salt, and the expiry. Browsers never send the fragment to the server, and the second key or passphrase is not part of it.</li>
        <li>The management link <code>/m#…</code> carries the <code>locator</code> and <code>M</code>; it cannot decrypt anything.</li>
        <li>On load, the page copies the fragment into memory and calls <code>history.replaceState</code> to remove it from the address bar before any secret UI renders. The application never writes it to local storage, cookies, or session state. The browser itself may still keep the full URL in its visit history, as it does for any link you open.</li>
        <li>Capabilities travel only in POST bodies, never in URLs. Every API response carries <code>Cache-Control: no-store</code> and <code>Referrer-Policy: no-referrer</code>. Request bodies, capabilities, locators, and ciphertext are not logged. The application runs under a strict Content Security Policy with no third-party scripts on any page that handles keys.</li>
      </ul>
    </InfoSection>

    <InfoSection title="4. What the service stores">
      <ul>
        <li><strong>Private R2 bucket</strong> — the exact envelope bytes under a random object key that is not derived from the locator. The bucket is reachable only through the Worker.</li>
        <li><strong>One Durable Object per transfer</strong> (SQLite, keyed by locator) — the R2 object key, the envelope&apos;s SHA-256 digest and length, the remaining number of opens, expiry, state, and <em>HMAC-SHA-256 tags</em> of the retrieve and manage tokens.</li>
        <li>The tags are computed with a versioned 32-byte HMAC key that lives only as a Worker secret, outside the stored state. Raw tokens are never stored.</li>
      </ul>
      <p>A copy of both stores yields ciphertext, sizes, timestamps, and policy metadata. It contains no content key, seed, passphrase, second key, or usable capability.</p>
    </InfoSection>

    <InfoSection title="5. Opening the secret">
      <ul>
        <li>The recipient&apos;s browser reads <code>S</code> from the fragment, takes the passphrase or second key if one is required, and re-derives <code>locator</code>, <code>contentKey</code>, and <code>retrieveToken</code> with the same HKDF schedule. Opening a page or any <code>GET</code> request consumes nothing.</li>
        <li>Pressing open sends <code>POST /api/v1/sends/retrieve</code> with the locator and the retrieve token.</li>
        <li>The Durable Object recomputes the HMAC tag, compares it with <code>crypto.subtle.verify</code>, reads the R2 object, checks its length and digest, and in one transaction rechecks state and expiry and decrements the counter. Only then are the envelope bytes returned. The last open closes access and starts deleting the R2 object.</li>
        <li>A wrong factor produces a wrong token. The server answers with the same generic <code>unavailable</code> response it gives for a missing, expired, or revoked transfer, and releases no ciphertext. Each transfer serializes guesses: a failure delays the next attempt with exponential backoff starting at 250&nbsp;ms. The cap is 30&nbsp;s for capabilities that carry at least 128 random bits, and one hour where a passphrase could be guessed.</li>
        <li>The browser validates the header, decrypts with AES-256-GCM, requires the envelope&apos;s factor mode to match the link, and rejects content past <code>min(clientNotAfter, serverExpiresAt)</code>. Decrypted text is rendered as plain text, never as HTML or Markdown.</li>
      </ul>
    </InfoSection>

    <InfoSection title="6. Deletion">
      <ul>
        <li>The final open, a revoke from the management link, or expiry moves the transfer to a terminal state inside the Durable Object, then attempts to delete the R2 object. A failed delete is retried from an alarm with backoff; access stays closed meanwhile.</li>
        <li>At expiry the Durable Object wipes its own storage. A small tombstone without ciphertext remains until the original expiry so status queries stay consistent.</li>
        <li>A 31-day R2 lifecycle rule is only a backstop for orphaned objects; it is not the access-control clock.</li>
      </ul>
      <p>Deletion removes the active copy. Kryptex does not claim immediate erasure from provider backups, and it cannot remove plaintext a recipient already opened.</p>
    </InfoSection>

    <InfoSection title="Requesting a secret">
      <p>The request flow reverses the direction and adds public-key encryption so the person answering never needs a shared secret:</p>
      <ul>
        <li>The owner&apos;s browser draws a 16-byte request locator and two 32-byte seeds. The owner seed derives the owner token and an <strong>X25519 key pair</strong>; the private key exists only in the owner&apos;s browser and is re-derived from the pickup link <code>/i#…</code>.</li>
        <li>The form definition is encrypted as a <code>KXE1</code> envelope with AES-256-GCM under a key from the write seed and the factor. The write link <code>/r#…</code> carries the write seed, the factor mode, the salt, and the owner&apos;s public key.</li>
        <li>The writer&apos;s browser decrypts the form, verifies its digest and public key, and encrypts the answers with <strong>HPKE</strong> (RFC 9180 base mode: DHKEM X25519, HKDF-SHA-256, AES-256-GCM) into a <code>KXR1</code> envelope bound to the request locator and form digest. The same bucket padding applies.</li>
        <li>Submission is write-once and pickup is read-once; both are enforced by the same Durable Object transaction pattern. A receipt — SHA-256 over the stored response bytes — lets both sides compare what was submitted and what was picked up.</li>
      </ul>
    </InfoSection>
  </div>;
}
