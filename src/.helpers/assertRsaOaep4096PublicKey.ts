import { ZeyraError } from "../.errors/class.js";
import { decodeBase64Url } from "./decodeBase64Url.js";

const RSA_OAEP_ALG = "RSA-OAEP-256";
const RSA_OAEP_USE = "enc";
const RSA_MODULUS_BYTES = 512;
const RSA_PUBLIC_OPS = ["wrapKey", "encrypt"] as const;

export function assertRsaOaep4096PublicKey(
  jwk: JsonWebKey,
  context = "key",
): void {
  if (!jwk || typeof jwk !== "object") {
    throw new ZeyraError(
      "RSA_OAEP_PUBLIC_KEY_EXPECTED",
      `${context}: expected an RSA-OAEP public JWK.`,
    );
  }

  if (jwk.kty !== "RSA") {
    throw new ZeyraError(
      "RSA_OAEP_PUBLIC_KEY_EXPECTED",
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
    if (!ops.has("wrapKey")) {
      throw new ZeyraError(
        "RSA_OAEP_KEY_OPS_INVALID",
        `${context}: key_ops must include wrapKey.`,
      );
    }
    for (const op of ops) {
      if (!RSA_PUBLIC_OPS.includes(op as (typeof RSA_PUBLIC_OPS)[number])) {
        throw new ZeyraError(
          "RSA_OAEP_KEY_OPS_INVALID",
          `${context}: unexpected key_ops value.`,
        );
      }
    }
  }

  if (typeof jwk.n !== "string" || typeof jwk.e !== "string") {
    throw new ZeyraError(
      "RSA_OAEP_PUBLIC_KEY_EXPECTED",
      `${context}: missing modulus or exponent.`,
    );
  }

  if (
    typeof jwk.d === "string" ||
    typeof jwk.p === "string" ||
    typeof jwk.q === "string" ||
    typeof jwk.dp === "string" ||
    typeof jwk.dq === "string" ||
    typeof jwk.qi === "string"
  ) {
    throw new ZeyraError(
      "RSA_OAEP_PUBLIC_KEY_EXPECTED",
      `${context}: private parameters are not allowed.`,
    );
  }

  const modulus = decodeBase64Url(jwk.n, `${context}: modulus`);
  if (modulus.byteLength !== RSA_MODULUS_BYTES) {
    throw new ZeyraError(
      "RSA_OAEP_MODULUS_LENGTH_INVALID",
      `${context}: expected 4096-bit modulus.`,
    );
  }

  const exponent = decodeBase64Url(jwk.e, `${context}: exponent`);
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
