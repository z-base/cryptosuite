import { CryptosuiteError } from "../../.errors/class.js";
import { assertSubtleAvailable } from "../../.helpers/assertSubtleAvailable.js";
import type { SignJWK, VerifyJWK } from "../index.js";

export async function generateVerificationPair(): Promise<{
  signJwk: SignJWK;
  verifyJwk: VerifyJWK;
}> {
  assertSubtleAvailable("generateVerificationPair");
  let verificationPair: CryptoKeyPair;
  try {
    verificationPair = await crypto.subtle.generateKey(
      { name: "Ed25519" },
      true,
      ["sign", "verify"],
    );
  } catch {
    throw new CryptosuiteError(
      "ED25519_UNSUPPORTED",
      "generateVerificationPair: Ed25519 is not supported.",
    );
  }
  const signJwk = (await crypto.subtle.exportKey(
    "jwk",
    verificationPair.privateKey,
  )) as SignJWK;
  const verifyJwk = (await crypto.subtle.exportKey(
    "jwk",
    verificationPair.publicKey,
  )) as VerifyJWK;
  return { signJwk, verifyJwk };
}
