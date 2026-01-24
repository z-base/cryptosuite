import type { UnwrapJWK, WrapJWK } from "../../.types/jwk.js";

export async function generateExchangePair(): Promise<{
  wrapJwk: WrapJWK;
  unwrapJwk: UnwrapJWK;
}> {
  const exchangePair = await crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 4096,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["wrapKey", "unwrapKey"],
  );
  const wrapJwk = (await crypto.subtle.exportKey(
    "jwk",
    exchangePair.publicKey,
  )) as WrapJWK;
  const unwrapJwk = (await crypto.subtle.exportKey(
    "jwk",
    exchangePair.privateKey,
  )) as UnwrapJWK;
  return { wrapJwk, unwrapJwk };
}
