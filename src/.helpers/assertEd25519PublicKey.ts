import { fromBase64UrlString } from "bytecodec";
import { ZeyraError } from "../.errors/class.js";

const ED25519_ALG = "EdDSA";
const ED25519_CURVE = "Ed25519";
const ED25519_USE = "sig";
const ED25519_BYTES = 32;
const ED25519_PUBLIC_OPS = ["verify"] as const;

export function assertEd25519PublicKey(
  jwk: JsonWebKey,
  context = "key",
): void {
  if (!jwk || typeof jwk !== "object") {
    throw new ZeyraError(
      "ED25519_PUBLIC_KEY_EXPECTED",
      `${context}: expected an Ed25519 public JWK.`,
    );
  }

  if (jwk.kty !== "OKP") {
    throw new ZeyraError(
      "ED25519_PUBLIC_KEY_EXPECTED",
      `${context}: expected kty OKP.`,
    );
  }

  if (jwk.crv !== ED25519_CURVE) {
    throw new ZeyraError(
      "ED25519_CURVE_INVALID",
      `${context}: expected curve ${ED25519_CURVE}.`,
    );
  }

  if (jwk.alg && jwk.alg !== ED25519_ALG) {
    throw new ZeyraError(
      "ED25519_ALG_INVALID",
      `${context}: expected alg ${ED25519_ALG}.`,
    );
  }

  if (jwk.use && jwk.use !== ED25519_USE) {
    throw new ZeyraError(
      "ED25519_USE_INVALID",
      `${context}: expected use ${ED25519_USE}.`,
    );
  }

  if (jwk.key_ops) {
    if (!Array.isArray(jwk.key_ops)) {
      throw new ZeyraError(
        "ED25519_KEY_OPS_INVALID",
        `${context}: key_ops must be an array.`,
      );
    }
    const ops = new Set(jwk.key_ops);
    if (!ops.has("verify")) {
      throw new ZeyraError(
        "ED25519_KEY_OPS_INVALID",
        `${context}: key_ops must include verify.`,
      );
    }
    for (const op of ops) {
      if (!ED25519_PUBLIC_OPS.includes(op as (typeof ED25519_PUBLIC_OPS)[number])) {
        throw new ZeyraError(
          "ED25519_KEY_OPS_INVALID",
          `${context}: unexpected key_ops value.`,
        );
      }
    }
  }

  if (typeof jwk.x !== "string") {
    throw new ZeyraError(
      "ED25519_PUBLIC_KEY_EXPECTED",
      `${context}: missing public key.`,
    );
  }

  if (typeof jwk.d === "string") {
    throw new ZeyraError(
      "ED25519_PUBLIC_KEY_EXPECTED",
      `${context}: private parameters are not allowed.`,
    );
  }

  let x: Uint8Array;
  try {
    x = fromBase64UrlString(jwk.x);
  } catch {
    throw new ZeyraError(
      "BASE64URL_INVALID",
      `${context}: invalid base64url key material.`,
    );
  }
  if (x.byteLength !== ED25519_BYTES) {
    throw new ZeyraError(
      "ED25519_KEY_SIZE_INVALID",
      `${context}: expected 32-byte public key.`,
    );
  }
}
