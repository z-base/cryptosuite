import { UnwrappingAgent } from "../UnwrappingAgent/class.js";

export class UnwrappingCluster {
  static #agents = new WeakMap<JsonWebKey, WeakRef<UnwrappingAgent>>();

  static #loadAgent(unwrappingJwk: JsonWebKey): UnwrappingAgent {
    const weakRef = UnwrappingCluster.#agents.get(unwrappingJwk);
    let agent = weakRef?.deref();
    if (!agent) {
      agent = new UnwrappingAgent(unwrappingJwk);
      UnwrappingCluster.#agents.set(unwrappingJwk, new WeakRef(agent));
    }
    return agent;
  }

  static async unwrap(
    unwrappingJwk: JsonWebKey,
    wrapped: ArrayBuffer
  ): Promise<JsonWebKey> {
    const agent = UnwrappingCluster.#loadAgent(unwrappingJwk);
    return await agent.unwrap(wrapped);
  }
}
