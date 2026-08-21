import { useState } from "react";
import type { SendPayload } from "@kryptex/contracts/payloads";
import { decryptSendEnvelope, deriveSendRecipientKeys, encodeBase64Url } from "@kryptex/crypto";
import { useClient } from "../client-context";
import { checkedResponseExpiry, classifyConsumingFailure, consumeBundle, factorFromInput } from "../crypto-flow";
import { formatOpens } from "../format";
import type { FragmentCapture } from "../fragment";
import { AmbiguousNotice, FactorInput, FragmentNotice, OperationNotice, PageIntro, SecretField, StatusMessage, normalizedFactorInput, type OperationState } from "../ui";

export function RetrievePage({ capture }: { readonly capture: FragmentCapture }) {
  const client = useClient();
  const [bundle] = useState(() => consumeBundle(capture, 1));
  const [factor, setFactor] = useState("");
  const [state, setState] = useState<OperationState>("idle");
  const [payload, setPayload] = useState<SendPayload | null>(null);
  const [remaining, setRemaining] = useState<number | null>(null);

  async function open(): Promise<void> {
    if (bundle?.kind !== 1) return;
    setState("working");
    let responseReleased = false;
    try {
      const factorBytes = await factorFromInput(bundle.factorMode, bundle.salt, normalizedFactorInput(bundle.factorMode, factor));
      const keys = await deriveSendRecipientKeys(bundle.sendSeed, bundle.factorMode, factorBytes);
      const response = await client.retrieveSend({ locator: encodeBase64Url(keys.locator), retrieveToken: encodeBase64Url(keys.retrieveToken) });
      responseReleased = true;
      const serverExpiresAt = checkedResponseExpiry(bundle.serverExpiresAt, response.metadata.serverExpiresAt);
      const opened = await decryptSendEnvelope(response.bytes, keys.contentKey, bundle.factorMode, serverExpiresAt, Math.floor(Date.now() / 1_000));
      setPayload(opened.payload); setRemaining(response.metadata.remainingReleases); setState("done");
    } catch (error) { setState(classifyConsumingFailure(error, responseReleased)); }
  }

  if (payload !== null) {
    return <div className="task-page task-page--narrow">
      <PageIntro title="Here is the secret">
        <p>Copy what you need now. Reloading this page will not show it again{remaining === null ? "" : `, and the link has ${formatOpens(remaining)}`}.</p>
      </PageIntro>
      {payload.kind === "text"
        ? <SecretField codeLike={false} label="Secret text" value={payload.text} />
        : payload.fields.map((field) => <SecretField codeLike={field.concealed} key={field.label} label={field.label} value={field.value} />)}
      <StatusMessage tone="warning">Whatever you save is yours to protect from here on. Expiry deletes the stored copy; it cannot take back what was already released.</StatusMessage>
    </div>;
  }

  return <div className="task-page task-page--narrow">
    <PageIntro title="Someone sent you a secret">
      <p>The content is encrypted. Nothing is released until you ask for it below, and the sender allows only a limited number of opens.</p>
    </PageIntro>
    <FragmentNotice capture={capture} />
    <div className="simple-form">
      {bundle?.kind === 1 && bundle.factorMode !== 0
        ? <FactorInput mode={bundle.factorMode === 1 ? 1 : 2} onChange={setFactor} value={factor} />
        : null}
      {bundle?.kind !== 1
        ? capture.fragmentBytes === null
          ? null
          : <StatusMessage tone="danger">This link is not a valid Kryptex secret link. Ask the sender to send the whole link again — messengers often cut off the part after the <span className="mono">#</span>.</StatusMessage>
        : state === "unknown"
          ? <AmbiguousNotice>
            <p>An open may already have been counted. Trying again can use up another one.</p>
            <button className="primary-button" onClick={() => { void open(); }} type="button">Try again anyway</button>
          </AmbiguousNotice>
          : <button className="primary-button full-button" disabled={state === "working" || (bundle.factorMode !== 0 && factor.trim().length === 0)} onClick={() => { void open(); }} type="button">{state === "working" ? "Opening…" : "Open the secret"}</button>}
    </div>
    <OperationNotice state={state === "unknown" ? "idle" : state} />
  </div>;
}
