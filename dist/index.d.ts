/***/
import { CipherCluster, deriveCipherKey, generateCipherKey } from "./Cipher/index.js";
/***/
import { ExchangeCluster, generateExchangePair } from "./Exchange/index.js";
/***/
import { deriveHMACKey, generateHMACKey, HMACCluster } from "./HMAC/index.js";
/***/
import { deriveOID, generateOID, validateOID } from "./OID/index.js";
/***/
import { generateVerificationPair, VerificationCluster } from "./Verification/index.js";
/***/
export { generateCipherKey, deriveCipherKey, CipherAgent, CipherCluster, type CipherJWK, } from "./Cipher/index.js";
/***/
export { generateExchangePair, WrapAgent, UnwrapAgent, ExchangeCluster, type WrapJWK, type UnwrapJWK, } from "./Exchange/index.js";
/***/
export { generateHMACKey, deriveHMACKey, HMACAgent, HMACCluster, type HMACJWK, } from "./HMAC/index.js";
/***/
export { deriveOID, generateOID, validateOID, type OpaqueIdentifier, } from "./OID/index.js";
/***/
export { generateVerificationPair, SignAgent, VerifyAgent, VerificationCluster, type SignJWK, type VerifyJWK, } from "./Verification/index.js";
/***/
export declare class Cryptosuite {
    static readonly cipher: {
        encrypt: typeof CipherCluster.encrypt;
        decrypt: typeof CipherCluster.decrypt;
        deriveKey: typeof deriveCipherKey;
        generateKey: typeof generateCipherKey;
    };
    static readonly exchange: {
        wrap: typeof ExchangeCluster.wrap;
        unwrap: typeof ExchangeCluster.unwrap;
        generatePair: typeof generateExchangePair;
    };
    static readonly hmac: {
        sign: typeof HMACCluster.sign;
        verify: typeof HMACCluster.verify;
        deriveKey: typeof deriveHMACKey;
        generateKey: typeof generateHMACKey;
    };
    static readonly oid: {
        derive: typeof deriveOID;
        generate: typeof generateOID;
        validate: typeof validateOID;
    };
    static readonly verification: {
        sign: typeof VerificationCluster.sign;
        verify: typeof VerificationCluster.verify;
        generatePair: typeof generateVerificationPair;
    };
}
//# sourceMappingURL=index.d.ts.map