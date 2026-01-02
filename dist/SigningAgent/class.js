import { Bytes } from "bytecodec";
export class SigningAgent {
    keyPromise;
    constructor(signingJwk) {
        this.keyPromise = crypto.subtle.importKey("jwk", signingJwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
    }
    async sign(bytes) {
        const key = await this.keyPromise;
        return crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, Bytes.toBufferSource(bytes));
    }
}
//# sourceMappingURL=class.js.map