import { ZeyraError } from "../.errors/class.js";

export function decodeBase64Url(value: string, context = "base64url"): Uint8Array {
  if (typeof value !== "string") {
    throw new ZeyraError(
      "BASE64URL_INVALID",
      `${context}: expected a base64url string.`,
    );
  }

  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const pad = normalized.length % 4;
  if (pad === 1) {
    throw new ZeyraError(
      "BASE64URL_INVALID",
      `${context}: invalid length.`,
    );
  }

  const padded =
    pad === 0 ? normalized : `${normalized}${"=".repeat(4 - pad)}`;

  const alphabet =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  const bytes: number[] = [];
  let buffer = 0;
  let bits = 0;

  for (let i = 0; i < padded.length; i += 1) {
    const char = padded[i];
    if (char === "=") break;
    const index = alphabet.indexOf(char);
    if (index === -1) {
      throw new ZeyraError(
        "BASE64URL_INVALID",
        `${context}: invalid character.`,
      );
    }
    buffer = (buffer << 6) | index;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((buffer >> bits) & 0xff);
    }
  }

  return new Uint8Array(bytes);
}
