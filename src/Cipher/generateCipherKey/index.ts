import type { CipherJWK } from "../../.types/jwk.js";

export async function generateCipherKey(): Promise<CipherJWK> {
  const aesKey = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
  return (await crypto.subtle.exportKey("jwk", aesKey)) as CipherJWK;
}
