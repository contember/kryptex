export class KryptexCryptoError extends Error {
  readonly code: string;

  constructor(code: string) {
    super("Cryptographic operation failed");
    this.name = "KryptexCryptoError";
    this.code = code;
  }
}

export function fail(code: string): never {
  throw new KryptexCryptoError(code);
}

export async function opaqueFailure<T>(operation: () => Promise<T>, code = "crypto_failed"): Promise<T> {
  try {
    return await operation();
  } catch (error) {
    if (error instanceof KryptexCryptoError) {
      throw error;
    }
    return fail(code);
  }
}
