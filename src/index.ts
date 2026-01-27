/***/
import {
  CipherCluster,
  deriveCipherKey,
  generateCipherKey,
} from "./Cipher/index.js";
/***/
import { ExchangeCluster, generateExchangePair } from "./Exchange/index.js";
/***/
import { deriveHMACKey, generateHMACKey, HMACCluster } from "./HMAC/index.js";
/***/
import { deriveOID, generateOID, validateOID } from "./OID/index.js";
/***/
import {
  generateVerificationPair,
  VerificationCluster,
} from "./Verification/index.js";
/***/
export {
  generateCipherKey,
  deriveCipherKey,
  CipherAgent,
  CipherCluster,
  type CipherJWK,
} from "./Cipher/index.js";
/***/
export {
  generateExchangePair,
  WrapAgent,
  UnwrapAgent,
  ExchangeCluster,
  type WrapJWK,
  type UnwrapJWK,
} from "./Exchange/index.js";
/***/
export {
  generateHMACKey,
  deriveHMACKey,
  HMACAgent,
  HMACCluster,
  type HMACJWK,
} from "./HMAC/index.js";
/***/
export {
  deriveOID,
  generateOID,
  validateOID,
  type OpaqueIdentifier,
} from "./OID/index.js";
/***/
export {
  generateVerificationPair,
  SignAgent,
  VerifyAgent,
  VerificationCluster,
  type SignJWK,
  type VerifyJWK,
} from "./Verification/index.js";
/***/

export class Cryptosuite {
  static readonly cipher = {
    encrypt: CipherCluster.encrypt,
    decrypt: CipherCluster.decrypt,
    deriveKey: deriveCipherKey,
    generateKey: generateCipherKey,
  };
  static readonly exchange = {
    wrap: ExchangeCluster.wrap,
    unwrap: ExchangeCluster.unwrap,
    generatePair: generateExchangePair,
  };
  static readonly hmac = {
    sign: HMACCluster.sign,
    verify: HMACCluster.verify,
    deriveKey: deriveHMACKey,
    generateKey: generateHMACKey,
  };
  static readonly oid = {
    derive: deriveOID,
    generate: generateOID,
    validate: validateOID,
  };
  static readonly verification = {
    sign: VerificationCluster.sign,
    verify: VerificationCluster.verify,
    generatePair: generateVerificationPair,
  };
}
