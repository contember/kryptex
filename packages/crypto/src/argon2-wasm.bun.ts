// Bun has no `?init` WASM imports, so it instantiates the same argon2id binaries from their resolved files.
async function instantiate(specifier: string, imports: WebAssembly.Imports): Promise<WebAssembly.Instance> {
  const response = await fetch(import.meta.resolve(specifier));
  return (await WebAssembly.instantiate(await response.arrayBuffer(), imports)).instance;
}

export const initializeArgon2Simd = (imports: WebAssembly.Imports): Promise<WebAssembly.Instance> => instantiate("argon2id/dist/simd.wasm", imports);
export const initializeArgon2NoSimd = (imports: WebAssembly.Imports): Promise<WebAssembly.Instance> => instantiate("argon2id/dist/no-simd.wasm", imports);
