import initArgon2idNoSimd from "argon2id/dist/no-simd.wasm?init";
import initArgon2idSimd from "argon2id/dist/simd.wasm?init";

export const initializeArgon2Simd: (imports: WebAssembly.Imports) => Promise<WebAssembly.Instance> = initArgon2idSimd;
export const initializeArgon2NoSimd: (imports: WebAssembly.Imports) => Promise<WebAssembly.Instance> = initArgon2idNoSimd;
