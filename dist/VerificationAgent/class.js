import { Bytes } from "bytecodec";
export class VerificationAgent {
    keyPromise;
    constructor(verificationJwk) {
        this.keyPromise = crypto.subtle.importKey("jwk", verificationJwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
    }
    async verify(bytes, signature) {
        const key = await this.keyPromise;
        return crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, signature, Bytes.toBufferSource(bytes));
    }
}
//# sourceMappingURL=class.js.map