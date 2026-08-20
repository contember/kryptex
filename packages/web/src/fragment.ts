export interface FragmentLocation {
  readonly hash: string;
  readonly pathname: string;
  readonly search: string;
}

export interface FragmentHistory {
  readonly state: unknown;
  replaceState(data: unknown, unused: string, url?: string | URL | null): void;
}

export interface FragmentCapture {
  readonly hadFragment: boolean;
  readonly fragmentBytes: Uint8Array | null;
  readonly canonicalPathname: string | null;
}

const SECRET_ROUTES = new Set(["/s", "/m", "/r", "/i"]);

export function canonicalSecretRoute(pathname: string): string | null {
  const withoutTrailingSlash = pathname.endsWith("/") && pathname.length === 3
    ? pathname.slice(0, -1)
    : pathname;

  return SECRET_ROUTES.has(withoutTrailingSlash) ? withoutTrailingSlash : null;
}

export function isSecretRoute(pathname: string): boolean {
  return canonicalSecretRoute(pathname) !== null;
}

export function captureAndScrubFragment(
  location: FragmentLocation,
  history: FragmentHistory
): FragmentCapture {
  const canonicalPathname = canonicalSecretRoute(location.pathname);
  if (canonicalPathname === null) {
    return { canonicalPathname: null, fragmentBytes: null, hadFragment: false };
  }

  const copiedFragment = location.hash.startsWith("#") ? location.hash.slice(1) : location.hash;
  const fragmentBytes = copiedFragment.length === 0 ? null : new TextEncoder().encode(copiedFragment);
  history.replaceState(history.state, "", canonicalPathname);

  return {
    canonicalPathname,
    fragmentBytes,
    hadFragment: fragmentBytes !== null
  };
}
