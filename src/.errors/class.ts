export type ZeyraErrorCode =
  | "BASE64URL_INVALID"
  | "BUFFER_SOURCE_EXPECTED"
  | "AES_GCM_KEY_EXPECTED"
  | "AES_GCM_ALG_INVALID"
  | "AES_GCM_KEY_SIZE_INVALID"
  | "AES_GCM_KEY_OPS_INVALID"
  | "AES_GCM_USE_INVALID"
  | "AES_GCM_RAW_LENGTH_INVALID"
  | "HMAC_KEY_EXPECTED"
  | "HMAC_ALG_INVALID"
  | "HMAC_KEY_SIZE_INVALID"
  | "HMAC_KEY_OPS_INVALID"
  | "HMAC_USE_INVALID"
  | "HMAC_RAW_LENGTH_INVALID"
  | "RSA_OAEP_PUBLIC_KEY_EXPECTED"
  | "RSA_OAEP_PRIVATE_KEY_EXPECTED"
  | "RSA_OAEP_ALG_INVALID"
  | "RSA_OAEP_MODULUS_LENGTH_INVALID"
  | "RSA_OAEP_EXPONENT_INVALID"
  | "RSA_OAEP_KEY_OPS_INVALID"
  | "RSA_OAEP_USE_INVALID"
  | "ECDSA_PUBLIC_KEY_EXPECTED"
  | "ECDSA_PRIVATE_KEY_EXPECTED"
  | "ECDSA_CURVE_INVALID"
  | "ECDSA_ALG_INVALID"
  | "ECDSA_COORDINATE_LENGTH_INVALID"
  | "ECDSA_KEY_OPS_INVALID"
  | "ECDSA_USE_INVALID";

export class ZeyraError extends Error {
  readonly code: ZeyraErrorCode;

  constructor(code: ZeyraErrorCode, message?: string) {
    const detail = message ?? code;
    super(`{zeyra} ${detail}`);
    this.code = code;
    this.name = "ZeyraError";
  }
}
