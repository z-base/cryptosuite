import { ZeyraError } from "../.errors/class.js";
import { decodeBase64Url } from "./decodeBase64Url.js";

const ECDSA_ALG = "ES256";
const ECDSA_CURVE = "P-256";
const ECDSA_USE = "sig";
const ECDSA_COORD_BYTES = 32;
const ECDSA_PRIVATE_OPS = ["sign"] as const;

export function assertEcdsaP256PrivateKey(
  jwk: JsonWebKey,
  context = "key",
): void {
  if (!jwk || typeof jwk !== "object") {
    throw new ZeyraError(
      "ECDSA_PRIVATE_KEY_EXPECTED",
      `${context}: expected an ECDSA private JWK.`,
    );
  }

  if (jwk.kty !== "EC") {
    throw new ZeyraError(
      "ECDSA_PRIVATE_KEY_EXPECTED",
      `${context}: expected kty EC.`,
    );
  }

  if (jwk.crv !== ECDSA_CURVE) {
    throw new ZeyraError(
      "ECDSA_CURVE_INVALID",
      `${context}: expected curve ${ECDSA_CURVE}.`,
    );
  }

  if (jwk.alg && jwk.alg !== ECDSA_ALG) {
    throw new ZeyraError(
      "ECDSA_ALG_INVALID",
      `${context}: expected alg ${ECDSA_ALG}.`,
    );
  }

  if (jwk.use && jwk.use !== ECDSA_USE) {
    throw new ZeyraError(
      "ECDSA_USE_INVALID",
      `${context}: expected use ${ECDSA_USE}.`,
    );
  }

  if (jwk.key_ops) {
    if (!Array.isArray(jwk.key_ops)) {
      throw new ZeyraError(
        "ECDSA_KEY_OPS_INVALID",
        `${context}: key_ops must be an array.`,
      );
    }
    const ops = new Set(jwk.key_ops);
    if (!ops.has("sign")) {
      throw new ZeyraError(
        "ECDSA_KEY_OPS_INVALID",
        `${context}: key_ops must include sign.`,
      );
    }
    for (const op of ops) {
      if (!ECDSA_PRIVATE_OPS.includes(op as (typeof ECDSA_PRIVATE_OPS)[number])) {
        throw new ZeyraError(
          "ECDSA_KEY_OPS_INVALID",
          `${context}: unexpected key_ops value.`,
        );
      }
    }
  }

  if (typeof jwk.x !== "string" || typeof jwk.y !== "string") {
    throw new ZeyraError(
      "ECDSA_PRIVATE_KEY_EXPECTED",
      `${context}: missing public coordinates.`,
    );
  }

  if (typeof jwk.d !== "string") {
    throw new ZeyraError(
      "ECDSA_PRIVATE_KEY_EXPECTED",
      `${context}: missing private scalar.`,
    );
  }

  const x = decodeBase64Url(jwk.x, `${context}: x`);
  const y = decodeBase64Url(jwk.y, `${context}: y`);
  const d = decodeBase64Url(jwk.d, `${context}: d`);
  if (
    x.byteLength !== ECDSA_COORD_BYTES ||
    y.byteLength !== ECDSA_COORD_BYTES ||
    d.byteLength !== ECDSA_COORD_BYTES
  ) {
    throw new ZeyraError(
      "ECDSA_COORDINATE_LENGTH_INVALID",
      `${context}: expected 32-byte coordinates.`,
    );
  }
}
