import { CryptosuiteError } from "../.errors/class.js";
import { getBufferSourceLength } from "./getBufferSourceLength.js";
import { AES_GCM_IV_BYTES } from "./shared.js";


export function assertAesGcmIv96(iv: Uint8Array | ArrayBuffer, context = "iv"): void {
  const length = getBufferSourceLength(iv, context);
  if (length !== AES_GCM_IV_BYTES) {
    throw new CryptosuiteError(
      "AES_GCM_IV_LENGTH_INVALID",
      `${context}: expected 12 bytes (96-bit).`,
    );
  }
}
