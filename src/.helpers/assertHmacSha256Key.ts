import { ZeyraError } from "../.errors/class.js";
import { decodeBase64Url } from "./decodeBase64Url.js";

const HMAC_ALG = "HS256";
const HMAC_USE = "sig";
const HMAC_KEY_BYTES = 32;
const HMAC_KEY_OPS = ["sign", "verify"] as const;

export function assertHmacSha256Key(jwk: JsonWebKey, context = "key"): void {
  if (!jwk || typeof jwk !== "object") {
    throw new ZeyraError("HMAC_KEY_EXPECTED", `${context}: expected an HMAC JWK.`);
  }

  if (jwk.kty !== "oct") {
    throw new ZeyraError(
      "HMAC_KEY_EXPECTED",
      `${context}: expected an octet JWK for HMAC.`,
    );
  }

  if (jwk.alg && jwk.alg !== HMAC_ALG) {
    throw new ZeyraError(
      "HMAC_ALG_INVALID",
      `${context}: expected alg ${HMAC_ALG}.`,
    );
  }

  if (jwk.use && jwk.use !== HMAC_USE) {
    throw new ZeyraError(
      "HMAC_USE_INVALID",
      `${context}: expected use ${HMAC_USE}.`,
    );
  }

  if (jwk.key_ops) {
    if (!Array.isArray(jwk.key_ops)) {
      throw new ZeyraError(
        "HMAC_KEY_OPS_INVALID",
        `${context}: key_ops must be an array.`,
      );
    }
    const ops = new Set(jwk.key_ops);
    for (const op of ops) {
      if (!HMAC_KEY_OPS.includes(op as (typeof HMAC_KEY_OPS)[number])) {
        throw new ZeyraError(
          "HMAC_KEY_OPS_INVALID",
          `${context}: unexpected key_ops value.`,
        );
      }
    }
    for (const required of HMAC_KEY_OPS) {
      if (!ops.has(required)) {
        throw new ZeyraError(
          "HMAC_KEY_OPS_INVALID",
          `${context}: key_ops must include ${required}.`,
        );
      }
    }
  }

  if (typeof jwk.k !== "string") {
    throw new ZeyraError("HMAC_KEY_EXPECTED", `${context}: missing key material.`);
  }

  const keyBytes = decodeBase64Url(jwk.k, `${context}: key material`);
  if (keyBytes.byteLength !== HMAC_KEY_BYTES) {
    throw new ZeyraError(
      "HMAC_KEY_SIZE_INVALID",
      `${context}: expected 256-bit key material.`,
    );
  }
}
