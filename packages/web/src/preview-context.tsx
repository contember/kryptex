import { createContext, useContext } from "react";
import type { ReactNode } from "react";

import type { KryptexAdapter } from "./preview-adapter";
import { localPreviewAdapter } from "./preview-adapter";

const PreviewAdapterContext = createContext<KryptexAdapter>(localPreviewAdapter);

export function PreviewAdapterProvider({ adapter, children }: { readonly adapter: KryptexAdapter; readonly children: ReactNode }) {
  return <PreviewAdapterContext.Provider value={adapter}>{children}</PreviewAdapterContext.Provider>;
}

export function usePreviewAdapter(): KryptexAdapter {
  return useContext(PreviewAdapterContext);
}
