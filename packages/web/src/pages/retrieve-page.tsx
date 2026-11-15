import { useState } from "react";
import type { SendPayload } from "@kryptex/contracts/payloads";
import { decryptSendEnvelope, deriveSendRecipientKeys, encodeBase64Url } from "@kryptex/crypto";
import { useClient } from "../client-context";
import { checkedResponseExpiry, classifyConsumingFailure, consumeBundle, factorFromInput } from "../crypto-flow";
import { formatOpens, isSensitiveField } from "../format";
import type { FragmentCapture } from "../fragment";
import { AmbiguousNotice, FactorInput, FragmentNotice, LinkProblem, OperationNotice, PageIntro, SecretField, StatusMessage, normalizedFactorInput, type OperationState } from "../ui";

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
      <PageIntro arrive title="Here is the secret">
        <p>Copy what you need now. Reloading this page will not show it again.{remaining === null ? "" : ` The link has ${formatOpens(remaining)}.`}</p>
      </PageIntro>
      {payload.kind === "text"
        ? <SecretField codeLike={false} label="Secret text" value={payload.text} />
        : payload.fields.map((field) => <SecretField codeLike={isSensitiveField(field.type)} key={field.label} label={field.label} value={field.value} />)}
      <StatusMessage tone="warning">From now on, keeping it safe is up to you. Expiry or revoking cannot take back a secret that was already opened.</StatusMessage>
    </div>;
  }

  if (bundle?.kind !== 1) return <LinkProblem capture={capture} flow="link" />;
  const needsFactor = bundle.factorMode !== 0;

  return <div className="task-page task-page--narrow">
    <PageIntro title="Someone sent you a secret">
      <p>It stays encrypted until you open it below. The sender allowed only a limited number of opens, and opening uses one.</p>
    </PageIntro>
    <FragmentNotice capture={capture} />
    <form className="simple-form" onSubmit={(event) => { event.preventDefault(); if (state !== "working" && state !== "unknown" && (!needsFactor || factor.trim().length > 0)) void open(); }}>
      {needsFactor
        ? <FactorInput mode={bundle.factorMode === 1 ? 1 : 2} onChange={setFactor} value={factor} />
        : null}
      {state === "unknown"
        ? <AmbiguousNotice>
          <p>An open may already have been counted. Trying again can use up another one.</p>
          <button className="primary-button" onClick={() => { void open(); }} type="button">Try again anyway</button>
        </AmbiguousNotice>
        : <button className="primary-button full-button" disabled={state === "working" || (needsFactor && factor.trim().length === 0)} type="submit">{state === "working" ? "Opening…" : "Open the secret"}</button>}
    </form>
    <OperationNotice state={state === "unknown" ? "idle" : state} />
  </div>;
}
