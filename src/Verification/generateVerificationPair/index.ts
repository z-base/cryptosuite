import type { SignJWK, VerifyJWK } from "../../.types/jwk.js";

export async function generateVerificationPair(): Promise<{
  signingJwk: SignJWK;
  verificationJwk: VerifyJWK;
}> {
  const verficationPair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  const verificationJwk = (await crypto.subtle.exportKey(
    "jwk",
    verficationPair.publicKey,
  )) as VerifyJWK;
  const signingJwk = (await crypto.subtle.exportKey(
    "jwk",
    verficationPair.privateKey,
  )) as SignJWK;
  return { signingJwk, verificationJwk };
}
