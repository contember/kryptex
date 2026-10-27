#!/usr/bin/env bun
import { KryptexClient } from "@kryptex/client";
import { run } from "./cli.js";

const result = await run(process.argv.slice(2), {
  clientFor: (origin) => new KryptexClient((input, init) => fetch(input, init), origin, "native"),
  cwd: process.cwd(),
  environment: process.env,
  now: () => Date.now(),
  sleep: (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)),
  stderr: (chunk) => {
    process.stderr.write(chunk);
  }
});
process.stdout.write("text" in result ? result.text : `${JSON.stringify(result.output)}\n`);
process.exitCode = result.exitCode;
