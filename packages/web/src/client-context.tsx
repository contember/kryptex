import { createContext, useContext, type ReactNode } from "react";
import { browserClient, type KryptexClient } from "./api-client";

const ClientContext = createContext<KryptexClient>(browserClient);

export function ClientProvider({ client, children }: { readonly client: KryptexClient; readonly children: ReactNode }) {
  return <ClientContext value={client}>{children}</ClientContext>;
}

export function useClient(): KryptexClient {
  return useContext(ClientContext);
}
