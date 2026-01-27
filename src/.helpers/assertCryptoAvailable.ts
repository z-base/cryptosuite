import { CryptosuiteError } from "../.errors/class.js";

export function assertCryptoAvailable(context = "crypto"): void {
  if (!globalThis.crypto) {
    throw new CryptosuiteError(
      "CRYPTO_UNAVAILABLE",
      `${context}: Web Crypto API is unavailable.`,
    );
  }
}
