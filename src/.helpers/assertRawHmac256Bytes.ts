import { ZeyraError } from "../.errors/class.js";
import { getBufferSourceLength } from "./getBufferSourceLength.js";

const HMAC_KEY_BYTES = 32;

export function assertRawHmac256Bytes(
  raw: BufferSource,
  context = "key material",
): void {
  const length = getBufferSourceLength(raw, context);
  if (length !== HMAC_KEY_BYTES) {
    throw new ZeyraError(
      "HMAC_RAW_LENGTH_INVALID",
      `${context}: expected 32 bytes (256-bit).`,
    );
  }
}
