declare module "argon2id/dist/no-simd.wasm?init" {
  const initialize: (imports: WebAssembly.Imports) => Promise<WebAssembly.Instance>;
  export default initialize;
}

declare module "argon2id/dist/simd.wasm?init" {
  const initialize: (imports: WebAssembly.Imports) => Promise<WebAssembly.Instance>;
  export default initialize;
}
