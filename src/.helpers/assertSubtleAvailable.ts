import { CryptosuiteError } from '../.errors/class.js'
import { assertCryptoAvailable } from './assertCryptoAvailable.js'

export function assertSubtleAvailable(context = 'crypto.subtle'): void {
  assertCryptoAvailable(context)
  if (!globalThis.crypto.subtle) {
    throw new CryptosuiteError(
      'SUBTLE_UNAVAILABLE',
      `${context}: SubtleCrypto is unavailable.`
    )
  }
}
