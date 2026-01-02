import { Bytes } from "bytecodec";
import { CipherAgent } from "../CipherAgent/class.js";
export class CipherCluster {
    static #agents = new WeakMap();
    static #loadAgent(cipherJwk) {
        const weakRef = CipherCluster.#agents.get(cipherJwk);
        let agent = weakRef?.deref();
        if (!agent) {
            agent = new CipherAgent(cipherJwk);
            CipherCluster.#agents.set(cipherJwk, new WeakRef(agent));
        }
        return agent;
    }
    static async encrypt(cipherJwk, resource) {
        const agent = CipherCluster.#loadAgent(cipherJwk);
        const bytes = Bytes.fromJSON(resource);
        const compressed = await Bytes.toCompressed(bytes);
        return await agent.encrypt(compressed);
    }
    static async decrypt(cipherJwk, artifact) {
        const agent = CipherCluster.#loadAgent(cipherJwk);
        const bytes = await agent.decrypt(artifact);
        const decompressed = await Bytes.fromCompressed(bytes);
        return Bytes.toJSON(decompressed);
    }
}
//# sourceMappingURL=class.js.map