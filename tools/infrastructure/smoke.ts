function requiredEnvironment(name: string): string {
  const value = process.env[name];
  if (value === undefined || value === "") {
    throw new Error(`${name} is required`);
  }
  return value;
}

function requireHeader(response: Response, name: string, expected?: string): void {
  const value = response.headers.get(name);
  if (value === null || (expected !== undefined && value !== expected)) {
    throw new Error(`Smoke check failed: ${name} is missing or invalid on ${response.url}`);
  }
}

async function smoke(): Promise<void> {
  const origin = requiredEnvironment("KRYPTEX_ORIGIN");
  const page = await fetch(`${origin}/`, { redirect: "error" });
  if (page.status !== 200) {
    throw new Error(`Smoke check failed: GET / returned ${page.status}`);
  }
  requireHeader(page, "Content-Security-Policy");
  requireHeader(page, "Referrer-Policy", "no-referrer");
  requireHeader(page, "X-Content-Type-Options", "nosniff");

  // A request without Origin is a native client request; a foreign Origin is what the gate must refuse.
  const forbidden = await fetch(`${origin}/api/v1/probe`, { headers: { Origin: "https://other.invalid" }, method: "GET", redirect: "error" });
  if (forbidden.status !== 403) {
    throw new Error(`Smoke check failed: foreign-origin API request returned ${forbidden.status}`);
  }
  requireHeader(forbidden, "Cache-Control", "no-store");
  requireHeader(forbidden, "Referrer-Policy", "no-referrer");

  const preflight = await fetch(`${origin}/api/v1/probe`, {
    headers: {
      "Access-Control-Request-Headers": "content-type",
      "Access-Control-Request-Method": "POST",
      Origin: origin
    },
    method: "OPTIONS",
    redirect: "error"
  });
  if (preflight.status !== 204) {
    throw new Error(`Smoke check failed: API preflight returned ${preflight.status}`);
  }
  requireHeader(preflight, "Access-Control-Allow-Origin", origin);
  requireHeader(preflight, "Access-Control-Allow-Methods", "POST, OPTIONS");
  requireHeader(preflight, "Cache-Control", "no-store");
  console.log(`Deployment smoke checks passed: ${origin}`);
}

try {
  await smoke();
} catch (error) {
  console.error(error instanceof Error ? error.message : "Deployment smoke check failed");
  process.exitCode = 1;
}
