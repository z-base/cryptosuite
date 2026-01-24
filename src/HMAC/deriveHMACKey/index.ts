import { assertRawHmac256Bytes } from "../../.helpers/assertRawHmac256Bytes.js";
import type { HMACJWK } from "../../.types/jwk.js";

export async function deriveHMACKey(first: BufferSource): Promise<HMACJWK> {
  assertRawHmac256Bytes(first, "deriveHMACKey");
  const key = await crypto.subtle.importKey(
    "raw",
    first,
    { name: "HMAC", hash: "SHA-256" },
    true,
    ["sign", "verify"],
  );

  return (await crypto.subtle.exportKey("jwk", key)) as HMACJWK;
}
