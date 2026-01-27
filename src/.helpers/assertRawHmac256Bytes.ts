import { CryptosuiteError } from "../.errors/class.js";
import { getBufferSourceLength } from "./getBufferSourceLength.js";
import { HMAC_KEY_BYTES } from "./shared.js";


export function assertRawHmac256Bytes(
  raw: Uint8Array | ArrayBuffer,
  context = "key material",
): void {
  const length = getBufferSourceLength(raw, context);
  if (length !== HMAC_KEY_BYTES) {
    throw new CryptosuiteError(
      "HMAC_RAW_LENGTH_INVALID",
      `${context}: expected 32 bytes (256-bit).`,
    );
  }
}
