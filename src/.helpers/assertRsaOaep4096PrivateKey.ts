import { fromBase64UrlString } from "bytecodec";
import { ZeyraError } from "../.errors/class.js";

const RSA_OAEP_ALG = "RSA-OAEP-256";
const RSA_OAEP_USE = "enc";
const RSA_MODULUS_BYTES = 512;
const RSA_PRIVATE_OPS = ["unwrapKey", "decrypt"] as const;

export function assertRsaOaep4096PrivateKey(
  jwk: JsonWebKey,
  context = "key",
): void {
  if (!jwk || typeof jwk !== "object") {
    throw new ZeyraError(
      "RSA_OAEP_PRIVATE_KEY_EXPECTED",
      `${context}: expected an RSA-OAEP private JWK.`,
    );
  }

  if (jwk.kty !== "RSA") {
    throw new ZeyraError(
      "RSA_OAEP_PRIVATE_KEY_EXPECTED",
      `${context}: expected kty RSA.`,
    );
  }

  if (jwk.alg && jwk.alg !== RSA_OAEP_ALG) {
    throw new ZeyraError(
      "RSA_OAEP_ALG_INVALID",
      `${context}: expected alg ${RSA_OAEP_ALG}.`,
    );
  }

  if (jwk.use && jwk.use !== RSA_OAEP_USE) {
    throw new ZeyraError(
      "RSA_OAEP_USE_INVALID",
      `${context}: expected use ${RSA_OAEP_USE}.`,
    );
  }

  if (jwk.key_ops) {
    if (!Array.isArray(jwk.key_ops)) {
      throw new ZeyraError(
        "RSA_OAEP_KEY_OPS_INVALID",
        `${context}: key_ops must be an array.`,
      );
    }
    const ops = new Set(jwk.key_ops);
    if (!ops.has("unwrapKey")) {
      throw new ZeyraError(
        "RSA_OAEP_KEY_OPS_INVALID",
        `${context}: key_ops must include unwrapKey.`,
      );
    }
    for (const op of ops) {
      if (!RSA_PRIVATE_OPS.includes(op as (typeof RSA_PRIVATE_OPS)[number])) {
        throw new ZeyraError(
          "RSA_OAEP_KEY_OPS_INVALID",
          `${context}: unexpected key_ops value.`,
        );
      }
    }
  }

  if (typeof jwk.n !== "string" || typeof jwk.e !== "string") {
    throw new ZeyraError(
      "RSA_OAEP_PRIVATE_KEY_EXPECTED",
      `${context}: missing modulus or exponent.`,
    );
  }

  if (typeof jwk.d !== "string") {
    throw new ZeyraError(
      "RSA_OAEP_PRIVATE_KEY_EXPECTED",
      `${context}: missing private exponent.`,
    );
  }

  let modulus: Uint8Array;
  try {
    modulus = fromBase64UrlString(jwk.n);
  } catch {
    throw new ZeyraError(
      "BASE64URL_INVALID",
      `${context}: invalid base64url modulus.`,
    );
  }
  if (modulus.byteLength !== RSA_MODULUS_BYTES) {
    throw new ZeyraError(
      "RSA_OAEP_MODULUS_LENGTH_INVALID",
      `${context}: expected 4096-bit modulus.`,
    );
  }

  let exponent: Uint8Array;
  try {
    exponent = fromBase64UrlString(jwk.e);
  } catch {
    throw new ZeyraError(
      "BASE64URL_INVALID",
      `${context}: invalid base64url exponent.`,
    );
  }
  let first = 0;
  while (first < exponent.length && exponent[first] === 0) first += 1;
  const remaining = exponent.length - first;
  if (
    remaining !== 3 ||
    exponent[first] !== 0x01 ||
    exponent[first + 1] !== 0x00 ||
    exponent[first + 2] !== 0x01
  ) {
    throw new ZeyraError(
      "RSA_OAEP_EXPONENT_INVALID",
      `${context}: expected exponent 65537.`,
    );
  }
}
