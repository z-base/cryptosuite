import type { SignJWK, VerifyJWK } from "../../.types/jwk.js";

export async function generateVerificationPair(): Promise<{
  signingJwk: SignJWK;
  verificationJwk: VerifyJWK;
}> {
  const verificationPair = await crypto.subtle.generateKey(
    { name: "Ed25519" },
    true,
    ["sign", "verify"],
  );
  const verificationJwk = (await crypto.subtle.exportKey(
    "jwk",
    verificationPair.publicKey,
  )) as VerifyJWK;
  const signingJwk = (await crypto.subtle.exportKey(
    "jwk",
    verificationPair.privateKey,
  )) as SignJWK;
  return { signingJwk, verificationJwk };
}
