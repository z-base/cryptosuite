import { ZeyraError } from "../.errors/class.js";
import { getBufferSourceLength } from "./getBufferSourceLength.js";

const AES_GCM_IV_BYTES = 12;

export function assertAesGcmIv96(iv: BufferSource, context = "iv"): void {
  const length = getBufferSourceLength(iv, context);
  if (length !== AES_GCM_IV_BYTES) {
    throw new ZeyraError(
      "AES_GCM_IV_LENGTH_INVALID",
      `${context}: expected 12 bytes (96-bit).`,
    );
  }
}
