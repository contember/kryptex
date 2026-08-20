export type OpenVerificationTab = (url: string, target: string, features: string) => void;

export function openIsolatedVerification(openTab: OpenVerificationTab): void {
  openTab("/gate", "_blank", "noopener,noreferrer");
}
