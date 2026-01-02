import { Bytes } from "bytecodec";
export class CipherAgent {
    keyPromise;
    constructor(cipherJwk) {
        this.keyPromise = crypto.subtle.importKey("jwk", cipherJwk, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
    }
    async encrypt(plaintext) {
        const key = await this.keyPromise;
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, Bytes.toBufferSource(plaintext));
        return { iv, ciphertext };
    }
    async decrypt({ iv, ciphertext, }) {
        const key = await this.keyPromise;
        const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv: Bytes.toBufferSource(iv) }, key, ciphertext);
        return new Uint8Array(plaintext);
    }
}
//# sourceMappingURL=class.js.map