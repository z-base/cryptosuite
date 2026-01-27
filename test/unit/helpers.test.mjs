import assert from "node:assert/strict";
import test from "node:test";
import { toBase64UrlString } from "bytecodec";
import { CryptosuiteError } from "../../dist/.errors/class.js";
import { assertCryptoAvailable } from "../../dist/.helpers/assertCryptoAvailable.js";
import { assertSubtleAvailable } from "../../dist/.helpers/assertSubtleAvailable.js";
import { assertGetRandomValuesAvailable } from "../../dist/.helpers/assertGetRandomValuesAvailable.js";
import { getBufferSourceLength } from "../../dist/.helpers/getBufferSourceLength.js";
import { assertAesGcmIv96 } from "../../dist/.helpers/assertAesGcmIv96.js";
import { assertRawAesGcm256Bytes } from "../../dist/.helpers/assertRawAesGcm256Bytes.js";
import { assertRawHmac256Bytes } from "../../dist/.helpers/assertRawHmac256Bytes.js";
import { assertAesGcm256Key } from "../../dist/.helpers/assertAesGcm256Key.js";
import { assertHmacSha256Key } from "../../dist/.helpers/assertHmacSha256Key.js";
import { assertEd25519PrivateKey } from "../../dist/.helpers/assertEd25519PrivateKey.js";
import { assertEd25519PublicKey } from "../../dist/.helpers/assertEd25519PublicKey.js";
import { assertRsaOaep4096PublicKey } from "../../dist/.helpers/assertRsaOaep4096PublicKey.js";
import { assertRsaOaep4096PrivateKey } from "../../dist/.helpers/assertRsaOaep4096PrivateKey.js";

const ORIGINAL_CRYPTO = globalThis.crypto;

function setCrypto(value) {
  Object.defineProperty(globalThis, "crypto", {
    value,
    configurable: true,
    writable: true,
  });
}

function restoreCrypto() {
  if (ORIGINAL_CRYPTO === undefined) {
    delete globalThis.crypto;
    return;
  }
  setCrypto(ORIGINAL_CRYPTO);
}

test.afterEach(() => {
  restoreCrypto();
});

function expectCode(fn, code) {
  let threw = false;
  try {
    fn();
  } catch (err) {
    threw = true;
    assert.ok(err instanceof CryptosuiteError);
    assert.equal(err.code, code);
  }
  assert.equal(threw, true);
}

test("CryptosuiteError uses code when message omitted", () => {
  const err = new CryptosuiteError("AES_GCM_UNSUPPORTED");
  assert.ok(err.message.includes("AES_GCM_UNSUPPORTED"));
});

const bytes32 = new Uint8Array(32).fill(1);
const bytes31 = new Uint8Array(31).fill(1);
const b64_32 = toBase64UrlString(bytes32);
const b64_31 = toBase64UrlString(bytes31);
const b64_invalid_len = "A";
const rsaN = toBase64UrlString(new Uint8Array(512).fill(2));
const rsaN_short = toBase64UrlString(new Uint8Array(511).fill(2));
const rsaE = toBase64UrlString(new Uint8Array([1, 0, 1]));
const rsaE_leadingZero = toBase64UrlString(new Uint8Array([0, 1, 0, 1]));
const rsaE_bad = toBase64UrlString(new Uint8Array([1, 0, 2]));

function aesJwk(overrides = {}) {
  return {
    kty: "oct",
    k: b64_32,
    alg: "A256GCM",
    use: "enc",
    key_ops: ["encrypt", "decrypt"],
    ...overrides,
  };
}

function hmacJwk(overrides = {}) {
  return {
    kty: "oct",
    k: b64_32,
    alg: "HS256",
    use: "sig",
    key_ops: ["sign", "verify"],
    ...overrides,
  };
}

function edPrivateJwk(overrides = {}) {
  return {
    kty: "OKP",
    crv: "Ed25519",
    x: b64_32,
    d: b64_32,
    alg: "EdDSA",
    use: "sig",
    key_ops: ["sign"],
    ...overrides,
  };
}

function edPublicJwk(overrides = {}) {
  return {
    kty: "OKP",
    crv: "Ed25519",
    x: b64_32,
    alg: "EdDSA",
    use: "sig",
    key_ops: ["verify"],
    ...overrides,
  };
}

function rsaPublicJwk(overrides = {}) {
  return {
    kty: "RSA",
    n: rsaN,
    e: rsaE,
    alg: "RSA-OAEP-256",
    use: "enc",
    key_ops: ["wrapKey"],
    ...overrides,
  };
}

function rsaPrivateJwk(overrides = {}) {
  return {
    kty: "RSA",
    n: rsaN,
    e: rsaE,
    d: b64_32,
    alg: "RSA-OAEP-256",
    use: "enc",
    key_ops: ["unwrapKey"],
    ...overrides,
  };
}

// Crypto availability

test("assertCryptoAvailable passes when crypto exists", () => {
  assertCryptoAvailable("test");
});

test("assertCryptoAvailable throws when crypto missing", () => {
  setCrypto(undefined);
  expectCode(() => assertCryptoAvailable("test"), "CRYPTO_UNAVAILABLE");
});

test("assertSubtleAvailable throws when subtle missing", () => {
  setCrypto({});
  expectCode(() => assertSubtleAvailable("test"), "SUBTLE_UNAVAILABLE");
});

test("assertGetRandomValuesAvailable throws when getRandomValues missing", () => {
  setCrypto({ subtle: {} });
  expectCode(() => assertGetRandomValuesAvailable("test"), "GET_RANDOM_VALUES_UNAVAILABLE");
});

// Buffer source helpers

test("getBufferSourceLength handles ArrayBuffer and Uint8Array", () => {
  const buf = new ArrayBuffer(12);
  const view = new Uint8Array(12);
  assert.equal(getBufferSourceLength(buf), 12);
  assert.equal(getBufferSourceLength(view), 12);
});

test("getBufferSourceLength throws on invalid input", () => {
  expectCode(() => getBufferSourceLength({}), "BUFFER_SOURCE_EXPECTED");
});

test("assertAesGcmIv96 accepts 12-byte iv and rejects others", () => {
  assertAesGcmIv96(new Uint8Array(12));
  expectCode(() => assertAesGcmIv96(new Uint8Array(11)), "AES_GCM_IV_LENGTH_INVALID");
});

test("assertRawAesGcm256Bytes enforces 32 bytes", () => {
  assertRawAesGcm256Bytes(new Uint8Array(32));
  assertRawAesGcm256Bytes(new ArrayBuffer(32));
  expectCode(() => assertRawAesGcm256Bytes(new Uint8Array(31)), "AES_GCM_RAW_LENGTH_INVALID");
});

test("assertRawHmac256Bytes enforces 32 bytes", () => {
  assertRawHmac256Bytes(new Uint8Array(32));
  assertRawHmac256Bytes(new ArrayBuffer(32));
  expectCode(() => assertRawHmac256Bytes(new Uint8Array(31)), "HMAC_RAW_LENGTH_INVALID");
});

// AES-GCM JWK

test("assertAesGcm256Key accepts valid JWKs (with and without key_ops)", () => {
  assertAesGcm256Key(aesJwk());
  assertAesGcm256Key(aesJwk({ key_ops: undefined }));
});

test("assertAesGcm256Key rejects invalid JWKs", () => {
  expectCode(() => assertAesGcm256Key(null), "AES_GCM_KEY_EXPECTED");
  expectCode(() => assertAesGcm256Key(aesJwk({ kty: "RSA" })), "AES_GCM_KEY_EXPECTED");
  expectCode(() => assertAesGcm256Key(aesJwk({ alg: "A128GCM" })), "AES_GCM_ALG_INVALID");
  expectCode(() => assertAesGcm256Key(aesJwk({ use: "sig" })), "AES_GCM_USE_INVALID");
  expectCode(() => assertAesGcm256Key(aesJwk({ key_ops: "encrypt" })), "AES_GCM_KEY_OPS_INVALID");
  expectCode(() => assertAesGcm256Key(aesJwk({ key_ops: ["encrypt", "sign"] })), "AES_GCM_KEY_OPS_INVALID");
  expectCode(() => assertAesGcm256Key(aesJwk({ key_ops: ["encrypt"] })), "AES_GCM_KEY_OPS_INVALID");
  expectCode(() => assertAesGcm256Key(aesJwk({ key_ops: ["decrypt"] })), "AES_GCM_KEY_OPS_INVALID");
  expectCode(() => assertAesGcm256Key(aesJwk({ k: undefined })), "AES_GCM_KEY_EXPECTED");
  expectCode(() => assertAesGcm256Key(aesJwk({ k: b64_invalid_len })), "BASE64URL_INVALID");
  expectCode(() => assertAesGcm256Key(aesJwk({ k: b64_31 })), "AES_GCM_KEY_SIZE_INVALID");
});

// HMAC JWK

test("assertHmacSha256Key accepts valid JWKs (with and without key_ops)", () => {
  assertHmacSha256Key(hmacJwk());
  assertHmacSha256Key(hmacJwk({ key_ops: undefined }));
});

test("assertHmacSha256Key rejects invalid JWKs", () => {
  expectCode(() => assertHmacSha256Key(null), "HMAC_KEY_EXPECTED");
  expectCode(() => assertHmacSha256Key(hmacJwk({ kty: "RSA" })), "HMAC_KEY_EXPECTED");
  expectCode(() => assertHmacSha256Key(hmacJwk({ alg: "HS384" })), "HMAC_ALG_INVALID");
  expectCode(() => assertHmacSha256Key(hmacJwk({ use: "enc" })), "HMAC_USE_INVALID");
  expectCode(() => assertHmacSha256Key(hmacJwk({ key_ops: "sign" })), "HMAC_KEY_OPS_INVALID");
  expectCode(() => assertHmacSha256Key(hmacJwk({ key_ops: ["sign", "encrypt"] })), "HMAC_KEY_OPS_INVALID");
  expectCode(() => assertHmacSha256Key(hmacJwk({ key_ops: ["sign"] })), "HMAC_KEY_OPS_INVALID");
  expectCode(() => assertHmacSha256Key(hmacJwk({ key_ops: ["verify"] })), "HMAC_KEY_OPS_INVALID");
  expectCode(() => assertHmacSha256Key(hmacJwk({ k: undefined })), "HMAC_KEY_EXPECTED");
  expectCode(() => assertHmacSha256Key(hmacJwk({ k: b64_invalid_len })), "BASE64URL_INVALID");
  expectCode(() => assertHmacSha256Key(hmacJwk({ k: b64_31 })), "HMAC_KEY_SIZE_INVALID");
});

// Ed25519 private JWK

test("assertEd25519PrivateKey accepts valid JWKs (with and without key_ops)", () => {
  assertEd25519PrivateKey(edPrivateJwk());
  assertEd25519PrivateKey(edPrivateJwk({ key_ops: undefined }));
});

test("assertEd25519PrivateKey rejects invalid JWKs", () => {
  expectCode(() => assertEd25519PrivateKey(null), "ED25519_PRIVATE_KEY_EXPECTED");
  expectCode(() => assertEd25519PrivateKey(edPrivateJwk({ kty: "EC" })), "ED25519_PRIVATE_KEY_EXPECTED");
  expectCode(() => assertEd25519PrivateKey(edPrivateJwk({ crv: "X25519" })), "ED25519_CURVE_INVALID");
  expectCode(() => assertEd25519PrivateKey(edPrivateJwk({ alg: "Ed448" })), "ED25519_ALG_INVALID");
  expectCode(() => assertEd25519PrivateKey(edPrivateJwk({ use: "enc" })), "ED25519_USE_INVALID");
  expectCode(() => assertEd25519PrivateKey(edPrivateJwk({ key_ops: "sign" })), "ED25519_KEY_OPS_INVALID");
  expectCode(() => assertEd25519PrivateKey(edPrivateJwk({ key_ops: ["verify"] })), "ED25519_KEY_OPS_INVALID");
  expectCode(() => assertEd25519PrivateKey(edPrivateJwk({ key_ops: ["sign", "wrapKey"] })), "ED25519_KEY_OPS_INVALID");
  expectCode(() => assertEd25519PrivateKey(edPrivateJwk({ x: undefined })), "ED25519_PRIVATE_KEY_EXPECTED");
  expectCode(() => assertEd25519PrivateKey(edPrivateJwk({ d: undefined })), "ED25519_PRIVATE_KEY_EXPECTED");
  expectCode(() => assertEd25519PrivateKey(edPrivateJwk({ x: b64_invalid_len })), "BASE64URL_INVALID");
  expectCode(() => assertEd25519PrivateKey(edPrivateJwk({ x: b64_31 })), "ED25519_KEY_SIZE_INVALID");
  expectCode(() => assertEd25519PrivateKey(edPrivateJwk({ d: b64_31 })), "ED25519_KEY_SIZE_INVALID");
});

// Ed25519 public JWK

test("assertEd25519PublicKey accepts valid JWKs (with and without key_ops)", () => {
  assertEd25519PublicKey(edPublicJwk());
  assertEd25519PublicKey(edPublicJwk({ key_ops: undefined }));
});

test("assertEd25519PublicKey rejects invalid JWKs", () => {
  expectCode(() => assertEd25519PublicKey(null), "ED25519_PUBLIC_KEY_EXPECTED");
  expectCode(() => assertEd25519PublicKey(edPublicJwk({ kty: "EC" })), "ED25519_PUBLIC_KEY_EXPECTED");
  expectCode(() => assertEd25519PublicKey(edPublicJwk({ crv: "X25519" })), "ED25519_CURVE_INVALID");
  expectCode(() => assertEd25519PublicKey(edPublicJwk({ alg: "Ed448" })), "ED25519_ALG_INVALID");
  expectCode(() => assertEd25519PublicKey(edPublicJwk({ use: "enc" })), "ED25519_USE_INVALID");
  expectCode(() => assertEd25519PublicKey(edPublicJwk({ key_ops: "verify" })), "ED25519_KEY_OPS_INVALID");
  expectCode(() => assertEd25519PublicKey(edPublicJwk({ key_ops: ["sign"] })), "ED25519_KEY_OPS_INVALID");
  expectCode(() => assertEd25519PublicKey(edPublicJwk({ key_ops: ["verify", "wrapKey"] })), "ED25519_KEY_OPS_INVALID");
  expectCode(() => assertEd25519PublicKey(edPublicJwk({ x: undefined })), "ED25519_PUBLIC_KEY_EXPECTED");
  expectCode(() => assertEd25519PublicKey(edPublicJwk({ d: b64_32 })), "ED25519_PUBLIC_KEY_EXPECTED");
  expectCode(() => assertEd25519PublicKey(edPublicJwk({ x: b64_invalid_len })), "BASE64URL_INVALID");
  expectCode(() => assertEd25519PublicKey(edPublicJwk({ x: b64_31 })), "ED25519_KEY_SIZE_INVALID");
});

// RSA public JWK

test("assertRsaOaep4096PublicKey accepts valid JWKs (with and without key_ops)", () => {
  assertRsaOaep4096PublicKey(rsaPublicJwk());
  assertRsaOaep4096PublicKey(rsaPublicJwk({ key_ops: undefined }));
  assertRsaOaep4096PublicKey(rsaPublicJwk({ e: rsaE_leadingZero }));
});

test("assertRsaOaep4096PublicKey rejects invalid JWKs", () => {
  expectCode(() => assertRsaOaep4096PublicKey(null), "RSA_OAEP_PUBLIC_KEY_EXPECTED");
  expectCode(() => assertRsaOaep4096PublicKey(rsaPublicJwk({ kty: "EC" })), "RSA_OAEP_PUBLIC_KEY_EXPECTED");
  expectCode(() => assertRsaOaep4096PublicKey(rsaPublicJwk({ alg: "RSA-OAEP" })), "RSA_OAEP_ALG_INVALID");
  expectCode(() => assertRsaOaep4096PublicKey(rsaPublicJwk({ use: "sig" })), "RSA_OAEP_USE_INVALID");
  expectCode(() => assertRsaOaep4096PublicKey(rsaPublicJwk({ key_ops: "wrapKey" })), "RSA_OAEP_KEY_OPS_INVALID");
  expectCode(() => assertRsaOaep4096PublicKey(rsaPublicJwk({ key_ops: ["encrypt"] })), "RSA_OAEP_KEY_OPS_INVALID");
  expectCode(() => assertRsaOaep4096PublicKey(rsaPublicJwk({ key_ops: ["wrapKey", "sign"] })), "RSA_OAEP_KEY_OPS_INVALID");
  expectCode(() => assertRsaOaep4096PublicKey(rsaPublicJwk({ n: undefined })), "RSA_OAEP_PUBLIC_KEY_EXPECTED");
  expectCode(() => assertRsaOaep4096PublicKey(rsaPublicJwk({ d: b64_32 })), "RSA_OAEP_PUBLIC_KEY_EXPECTED");
  expectCode(() => assertRsaOaep4096PublicKey(rsaPublicJwk({ n: b64_invalid_len })), "BASE64URL_INVALID");
  expectCode(() => assertRsaOaep4096PublicKey(rsaPublicJwk({ n: rsaN_short })), "RSA_OAEP_MODULUS_LENGTH_INVALID");
  expectCode(() => assertRsaOaep4096PublicKey(rsaPublicJwk({ e: b64_invalid_len })), "BASE64URL_INVALID");
  expectCode(() => assertRsaOaep4096PublicKey(rsaPublicJwk({ e: rsaE_bad })), "RSA_OAEP_EXPONENT_INVALID");
});

// RSA private JWK

test("assertRsaOaep4096PrivateKey accepts valid JWKs (with and without key_ops)", () => {
  assertRsaOaep4096PrivateKey(rsaPrivateJwk());
  assertRsaOaep4096PrivateKey(rsaPrivateJwk({ key_ops: undefined }));
  assertRsaOaep4096PrivateKey(rsaPrivateJwk({ e: rsaE_leadingZero }));
});

test("assertRsaOaep4096PrivateKey rejects invalid JWKs", () => {
  expectCode(() => assertRsaOaep4096PrivateKey(null), "RSA_OAEP_PRIVATE_KEY_EXPECTED");
  expectCode(() => assertRsaOaep4096PrivateKey(rsaPrivateJwk({ kty: "EC" })), "RSA_OAEP_PRIVATE_KEY_EXPECTED");
  expectCode(() => assertRsaOaep4096PrivateKey(rsaPrivateJwk({ alg: "RSA-OAEP" })), "RSA_OAEP_ALG_INVALID");
  expectCode(() => assertRsaOaep4096PrivateKey(rsaPrivateJwk({ use: "sig" })), "RSA_OAEP_USE_INVALID");
  expectCode(() => assertRsaOaep4096PrivateKey(rsaPrivateJwk({ key_ops: "unwrapKey" })), "RSA_OAEP_KEY_OPS_INVALID");
  expectCode(() => assertRsaOaep4096PrivateKey(rsaPrivateJwk({ key_ops: ["decrypt"] })), "RSA_OAEP_KEY_OPS_INVALID");
  expectCode(() => assertRsaOaep4096PrivateKey(rsaPrivateJwk({ key_ops: ["unwrapKey", "sign"] })), "RSA_OAEP_KEY_OPS_INVALID");
  expectCode(() => assertRsaOaep4096PrivateKey(rsaPrivateJwk({ n: undefined })), "RSA_OAEP_PRIVATE_KEY_EXPECTED");
  expectCode(() => assertRsaOaep4096PrivateKey(rsaPrivateJwk({ d: undefined })), "RSA_OAEP_PRIVATE_KEY_EXPECTED");
  expectCode(() => assertRsaOaep4096PrivateKey(rsaPrivateJwk({ n: b64_invalid_len })), "BASE64URL_INVALID");
  expectCode(() => assertRsaOaep4096PrivateKey(rsaPrivateJwk({ n: rsaN_short })), "RSA_OAEP_MODULUS_LENGTH_INVALID");
  expectCode(() => assertRsaOaep4096PrivateKey(rsaPrivateJwk({ e: b64_invalid_len })), "BASE64URL_INVALID");
  expectCode(() => assertRsaOaep4096PrivateKey(rsaPrivateJwk({ e: rsaE_bad })), "RSA_OAEP_EXPONENT_INVALID");
});
