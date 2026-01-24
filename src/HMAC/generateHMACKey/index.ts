import type { HMACJWK } from "../../.types/jwk.js";

export async function generateHMACKey(): Promise<HMACJWK> {
  const hmacKey = await crypto.subtle.generateKey(
    { name: "HMAC", hash: "SHA-256", length: 256 },
    true,
    ["sign", "verify"],
  );
  return (await crypto.subtle.exportKey("jwk", hmacKey)) as HMACJWK;
}
