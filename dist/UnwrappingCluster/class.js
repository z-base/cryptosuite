import { UnwrappingAgent } from "../UnwrappingAgent/class.js";
export class UnwrappingCluster {
    static #agents = new WeakMap();
    static #loadAgent(unwrappingJwk) {
        const weakRef = UnwrappingCluster.#agents.get(unwrappingJwk);
        let agent = weakRef?.deref();
        if (!agent) {
            agent = new UnwrappingAgent(unwrappingJwk);
            UnwrappingCluster.#agents.set(unwrappingJwk, new WeakRef(agent));
        }
        return agent;
    }
    static async unwrap(unwrappingJwk, wrapped) {
        const agent = UnwrappingCluster.#loadAgent(unwrappingJwk);
        return await agent.unwrap(wrapped);
    }
}
//# sourceMappingURL=class.js.map