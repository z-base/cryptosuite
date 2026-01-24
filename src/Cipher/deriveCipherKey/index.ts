import { assertRawAesGcm256Bytes } from "../../.helpers/assertRawAesGcm256Bytes.js";
import type { CipherJWK } from "../../.types/jwk.js";

export async function deriveCipherKey(
  second: BufferSource,
): Promise<CipherJWK> {
  assertRawAesGcm256Bytes(second, "deriveCipherKey");
  const key = await crypto.subtle.importKey(
    "raw",
    second,
    { name: "AES-GCM" },
    true,
    ["encrypt", "decrypt"]
  );
  return (await crypto.subtle.exportKey("jwk", key)) as CipherJWK;
}
