/***/
import { CipherCluster, deriveCipherKey, generateCipherKey, } from "./Cipher/index.js";
/***/
import { ExchangeCluster, generateExchangePair } from "./Exchange/index.js";
/***/
import { deriveHMACKey, generateHMACKey, HMACCluster } from "./HMAC/index.js";
/***/
import { deriveOID, generateOID, validateOID } from "./OID/index.js";
/***/
import { generateVerificationPair, VerificationCluster, } from "./Verification/index.js";
/***/
export { generateCipherKey, deriveCipherKey, CipherAgent, CipherCluster, } from "./Cipher/index.js";
/***/
export { generateExchangePair, WrapAgent, UnwrapAgent, ExchangeCluster, } from "./Exchange/index.js";
/***/
export { generateHMACKey, deriveHMACKey, HMACAgent, HMACCluster, } from "./HMAC/index.js";
/***/
export { deriveOID, generateOID, validateOID, } from "./OID/index.js";
/***/
export { generateVerificationPair, SignAgent, VerifyAgent, VerificationCluster, } from "./Verification/index.js";
/***/
export class Cryptosuite {
    static cipher = {
        encrypt: CipherCluster.encrypt,
        decrypt: CipherCluster.decrypt,
        deriveKey: deriveCipherKey,
        generateKey: generateCipherKey,
    };
    static exchange = {
        wrap: ExchangeCluster.wrap,
        unwrap: ExchangeCluster.unwrap,
        generatePair: generateExchangePair,
    };
    static hmac = {
        sign: HMACCluster.sign,
        verify: HMACCluster.verify,
        deriveKey: deriveHMACKey,
        generateKey: generateHMACKey,
    };
    static oid = {
        derive: deriveOID,
        generate: generateOID,
        validate: validateOID,
    };
    static verification = {
        sign: VerificationCluster.sign,
        verify: VerificationCluster.verify,
        generatePair: generateVerificationPair,
    };
}
//# sourceMappingURL=index.js.map