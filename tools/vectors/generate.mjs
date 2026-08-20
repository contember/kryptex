import { mkdir, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { deriveVectors } from "./derive.mjs";

const toolDirectory = dirname(fileURLToPath(import.meta.url));
const outputDirectory = resolve(toolDirectory, "../../vectors/v1");
const vectors = await deriveVectors();

await mkdir(outputDirectory, { recursive: true });
for (const [filename, value] of Object.entries(vectors)) {
  await writeFile(resolve(outputDirectory, filename), `${JSON.stringify(value, null, 2)}\n`);
}

console.log(`Wrote ${Object.keys(vectors).length} vector files to ${outputDirectory}`);
