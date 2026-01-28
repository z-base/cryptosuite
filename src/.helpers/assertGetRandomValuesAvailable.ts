import { CryptosuiteError } from '../.errors/class.js'
import { assertCryptoAvailable } from './assertCryptoAvailable.js'

export function assertGetRandomValuesAvailable(
  context = 'crypto.getRandomValues'
): void {
  assertCryptoAvailable(context)
  if (typeof globalThis.crypto.getRandomValues !== 'function') {
    throw new CryptosuiteError(
      'GET_RANDOM_VALUES_UNAVAILABLE',
      `${context}: crypto.getRandomValues is unavailable.`
    )
  }
}
