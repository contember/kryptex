export type CreationIntent = "request" | "send";

export function creationPath(intent: CreationIntent): "/request" | "/send" {
  return intent === "send" ? "/send" : "/request";
}

export function gatePath(intent: CreationIntent): string {
  return `/gate?intent=${intent}`;
}

export function parseCreationIntent(search: string): CreationIntent | null {
  const parameters = new URLSearchParams(search);
  if (parameters.size !== 1) return null;
  const intent = parameters.get("intent");
  return intent === "send" || intent === "request" ? intent : null;
}
