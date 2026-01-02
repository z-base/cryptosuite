import { Bytes } from "bytecodec";
import { SigningAgent } from "../SigningAgent/class.js";
export class SigningCluster {
    static #agents = new WeakMap();
    static #loadAgent(signingJwk) {
        const weakRef = SigningCluster.#agents.get(signingJwk);
        let agent = weakRef?.deref();
        if (!agent) {
            agent = new SigningAgent(signingJwk);
            SigningCluster.#agents.set(signingJwk, new WeakRef(agent));
        }
        return agent;
    }
    static async sign(signingJwk, value) {
        const agent = SigningCluster.#loadAgent(signingJwk);
        const bytes = Bytes.fromJSON(value);
        return await agent.sign(bytes);
    }
}
//# sourceMappingURL=class.js.map