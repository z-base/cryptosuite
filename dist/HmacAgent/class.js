export class HmacAgent {
    keyPromise;
    constructor(hmacJwk) {
        this.keyPromise = crypto.subtle.importKey("jwk", hmacJwk, { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
    }
    async sign(challenge) {
        const key = await this.keyPromise;
        return crypto.subtle.sign("HMAC", key, challenge);
    }
    async verify(challenge, signature) {
        const key = await this.keyPromise;
        return crypto.subtle.verify("HMAC", key, signature, challenge);
    }
}
//# sourceMappingURL=class.js.map