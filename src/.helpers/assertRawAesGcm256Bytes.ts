import { CryptosuiteError } from '../.errors/class.js'
import { getBufferSourceLength } from './getBufferSourceLength.js'
import { AES_GCM_KEY_BYTES } from './shared.js'

export function assertRawAesGcm256Bytes(
  raw: Uint8Array | ArrayBuffer,
  context = 'key material'
): void {
  const length = getBufferSourceLength(raw, context)
  if (length !== AES_GCM_KEY_BYTES) {
    throw new CryptosuiteError(
      'AES_GCM_RAW_LENGTH_INVALID',
      `${context}: expected 32 bytes (256-bit).`
    )
  }
}
