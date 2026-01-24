import { ZeyraError } from "../.errors/class.js";
import { getBufferSourceLength } from "./getBufferSourceLength.js";

const AES_GCM_KEY_BYTES = 32;

export function assertRawAesGcm256Bytes(
  raw: BufferSource,
  context = "key material",
): void {
  const length = getBufferSourceLength(raw, context);
  if (length !== AES_GCM_KEY_BYTES) {
    throw new ZeyraError(
      "AES_GCM_RAW_LENGTH_INVALID",
      `${context}: expected 32 bytes (256-bit).`,
    );
  }
}
