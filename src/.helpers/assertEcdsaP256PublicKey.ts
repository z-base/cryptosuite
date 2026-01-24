import { ZeyraError } from "../.errors/class.js";
import { decodeBase64Url } from "./decodeBase64Url.js";

const ECDSA_ALG = "ES256";
const ECDSA_CURVE = "P-256";
const ECDSA_USE = "sig";
const ECDSA_COORD_BYTES = 32;
const ECDSA_PUBLIC_OPS = ["verify"] as const;

export function assertEcdsaP256PublicKey(
  jwk: JsonWebKey,
  context = "key",
): void {
  if (!jwk || typeof jwk !== "object") {
    throw new ZeyraError(
      "ECDSA_PUBLIC_KEY_EXPECTED",
      `${context}: expected an ECDSA public JWK.`,
    );
  }

  if (jwk.kty !== "EC") {
    throw new ZeyraError(
      "ECDSA_PUBLIC_KEY_EXPECTED",
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
    if (!ops.has("verify")) {
      throw new ZeyraError(
        "ECDSA_KEY_OPS_INVALID",
        `${context}: key_ops must include verify.`,
      );
    }
    for (const op of ops) {
      if (!ECDSA_PUBLIC_OPS.includes(op as (typeof ECDSA_PUBLIC_OPS)[number])) {
        throw new ZeyraError(
          "ECDSA_KEY_OPS_INVALID",
          `${context}: unexpected key_ops value.`,
        );
      }
    }
  }

  if (typeof jwk.x !== "string" || typeof jwk.y !== "string") {
    throw new ZeyraError(
      "ECDSA_PUBLIC_KEY_EXPECTED",
      `${context}: missing public coordinates.`,
    );
  }

  if (typeof jwk.d === "string") {
    throw new ZeyraError(
      "ECDSA_PUBLIC_KEY_EXPECTED",
      `${context}: private parameters are not allowed.`,
    );
  }

  const x = decodeBase64Url(jwk.x, `${context}: x`);
  const y = decodeBase64Url(jwk.y, `${context}: y`);
  if (x.byteLength !== ECDSA_COORD_BYTES || y.byteLength !== ECDSA_COORD_BYTES) {
    throw new ZeyraError(
      "ECDSA_COORDINATE_LENGTH_INVALID",
      `${context}: expected 32-byte coordinates.`,
    );
  }
}
