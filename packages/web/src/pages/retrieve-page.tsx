import { useState } from "react";
import type { SendPayload } from "@kryptex/contracts/payloads";
import { decryptSendEnvelope, deriveSendRecipientKeys, encodeBase64Url } from "@kryptex/crypto";
import { useClient } from "../client-context";
import { checkedResponseExpiry, classifyConsumingFailure, consumeBundle, factorFromInput } from "../crypto-flow";
import type { FragmentCapture } from "../fragment";
import { AmbiguousNotice, FragmentNotice, OperationNotice, PageIntro, SecretField, StatusMessage, type OperationState } from "../ui";

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
      const factorBytes = await factorFromInput(bundle.factorMode, bundle.salt, factor);
      const keys = await deriveSendRecipientKeys(bundle.sendSeed, bundle.factorMode, factorBytes);
      const response = await client.retrieveSend({ locator: encodeBase64Url(keys.locator), retrieveToken: encodeBase64Url(keys.retrieveToken) });
      responseReleased = true;
      const serverExpiresAt = checkedResponseExpiry(bundle.serverExpiresAt, response.metadata.serverExpiresAt);
      const opened = await decryptSendEnvelope(response.bytes, keys.contentKey, bundle.factorMode, serverExpiresAt, Math.floor(Date.now() / 1_000));
      setPayload(opened.payload); setRemaining(response.metadata.remainingReleases); setState("done");
    } catch (error) { setState(classifyConsumingFailure(error, responseReleased)); }
  }

  if (payload !== null) return <div className="task-page task-page--narrow"><PageIntro title="Secret opened"><p>{remaining} releases remain.</p></PageIntro><StatusMessage tone="warning">A recipient can retain released plaintext. Expiry cannot revoke content that has already been released.</StatusMessage>{payload.kind === "text" ? <SecretField codeLike={false} label="Secret text" value={payload.text} /> : payload.fields.map((field) => <SecretField codeLike={field.concealed} key={field.label} label={field.label} value={field.value} />)}</div>;
  return <div className="task-page task-page--narrow"><PageIntro title="Open secret"><p>This action consumes one release.</p></PageIntro><FragmentNotice capture={capture} />{bundle?.kind === 1 && bundle.factorMode !== 0 ? <label><span>{bundle.factorMode === 1 ? "Passphrase" : "Second key"}</span><input autoComplete="off" onChange={(event) => { setFactor(event.currentTarget.value); }} spellCheck={false} type="password" value={factor} /></label> : null}{bundle?.kind !== 1 ? <StatusMessage tone="danger">This recipient link is invalid.</StatusMessage> : state === "unknown" ? <AmbiguousNotice>A release may already have been consumed. Retrying can consume another release.<button onClick={() => { void open(); }} type="button">Consume another release</button></AmbiguousNotice> : <button className="primary-button full-button" disabled={state === "working" || (bundle.factorMode !== 0 && factor.length === 0)} onClick={() => { void open(); }} type="button">Open once</button>}<OperationNotice state={state === "unknown" ? "idle" : state} /></div>;
}
