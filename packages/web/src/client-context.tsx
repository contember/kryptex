import { createContext, useContext, type ReactNode } from "react";
import { KryptexClient } from "@kryptex/client";

const ClientContext = createContext<KryptexClient>(new KryptexClient());

export function ClientProvider({ client, children }: { readonly client: KryptexClient; readonly children: ReactNode }) {
  return <ClientContext value={client}>{children}</ClientContext>;
}

export function useClient(): KryptexClient {
  return useContext(ClientContext);
}
