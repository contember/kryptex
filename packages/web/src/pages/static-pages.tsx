import { useState } from "react";
import { Link } from "react-router";

import { usePreviewOperation } from "../preview-hooks";
import { InfoSection, PageIntro, PreviewMark, StatusMessage } from "../ui";

export function HomePage() {
  return <div className="home-page"><div className="home-wordmark">Kryptex</div><h1>Send sensitive information without giving the service the readable secret.</h1><p>Encrypted in the browser. Shared by link. No account needed.</p><div className="home-actions"><Link className="primary-button" to="/send">Send secret</Link><Link className="secondary-button" to="/request">Request secret</Link></div><Link className="quiet-link" to="/security">Security</Link><p className="home-experimental">Experimental — not production-ready</p></div>;
}

export function GatePage() {
  const [ready, setReady] = useState(false);
  const operation = usePreviewOperation();
  async function prepare(): Promise<void> { await operation.run("authorize"); setReady(true); }
  return <div className="task-page task-page--narrow"><PageIntro title="Confirm you are human"><p>This separate page keeps verification away from your secret.</p></PageIntro><PreviewMark />{ready ? <StatusMessage tone="success">Ready. Return to the original tab and continue.</StatusMessage> : <button className="primary-button full-button" disabled={operation.phase === "working"} onClick={() => { void prepare(); }} type="button">{operation.phase === "working" ? "Checking…" : "Continue"}</button>}</div>;
}

export function SecurityPage() {
  return <div className="task-page"><PageIntro title="Security"><p>Kryptex is experimental. Do not use this preview for real secrets.</p></PageIntro><InfoSection title="What stays in your browser"><p>Readable secrets, passphrases, second keys, and encryption keys. The intended server stores encrypted bytes and tagged access tokens.</p></InfoSection><InfoSection title="What a link can and cannot do"><p>A separate second key reduces the damage from one compromised channel. A recipient can still keep anything they open. Expiry cannot take it back.</p></InfoSection><InfoSection title="Important limits"><p>Compromised browser code can read content while you use it. Weak passphrases can be guessed. One-time access depends on the server and platform working correctly.</p></InfoSection><Link className="quiet-link" to="/">Back</Link></div>;
}
