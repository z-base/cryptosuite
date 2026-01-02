export class WrappingAgent {
    keyPromise;
    constructor(wrappingJwk) {
        this.keyPromise = crypto.subtle.importKey("jwk", wrappingJwk, { name: "RSA-OAEP", hash: "SHA-256" }, false, ["wrapKey"]);
    }
    async wrap(cipherJwk) {
        const wrappingKey = await this.keyPromise;
        const aesKey = await crypto.subtle.importKey("jwk", cipherJwk, { name: "AES-GCM" }, true, ["encrypt", "decrypt"]);
        return crypto.subtle.wrapKey("jwk", aesKey, wrappingKey, {
            name: "RSA-OAEP",
        });
    }
}
//# sourceMappingURL=class.js.map