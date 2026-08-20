import type { WorkerEnv } from "./env.js";

const unavailableHeaders: HeadersInit = {
  "Cache-Control": "no-store",
  "Content-Type": "application/json; charset=utf-8",
  "Referrer-Policy": "no-referrer",
  "X-Content-Type-Options": "nosniff"
};

function notImplemented(): Response {
  return new Response('{"error":"not_implemented"}', {
    headers: unavailableHeaders,
    status: 501
  });
}

export class SendDurableObject {
  fetch(): Response {
    return notImplemented();
  }
}

export class RequestDurableObject {
  fetch(): Response {
    return notImplemented();
  }
}

export class CreatePermitDurableObject {
  fetch(): Response {
    return notImplemented();
  }
}

export default {
  fetch(): Response {
    return notImplemented();
  }
} satisfies ExportedHandler<WorkerEnv>;
