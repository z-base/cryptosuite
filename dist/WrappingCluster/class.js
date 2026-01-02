import { WrappingAgent } from "../WrappingAgent/class.js";
export class WrappingCluster {
    static #agents = new WeakMap();
    static #loadAgent(wrappingJwk) {
        const weakRef = WrappingCluster.#agents.get(wrappingJwk);
        let agent = weakRef?.deref();
        if (!agent) {
            agent = new WrappingAgent(wrappingJwk);
            WrappingCluster.#agents.set(wrappingJwk, new WeakRef(agent));
        }
        return agent;
    }
    static async wrap(wrappingJwk, cipherJwk) {
        const agent = WrappingCluster.#loadAgent(wrappingJwk);
        return await agent.wrap(cipherJwk);
    }
}
//# sourceMappingURL=class.js.map