import { WrappingAgent } from "../WrappingAgent/class.js";

export class WrappingCluster {
  static #agents = new WeakMap<JsonWebKey, WeakRef<WrappingAgent>>();

  static #loadAgent(wrappingJwk: JsonWebKey): WrappingAgent {
    const weakRef = WrappingCluster.#agents.get(wrappingJwk);
    let agent = weakRef?.deref();
    if (!agent) {
      agent = new WrappingAgent(wrappingJwk);
      WrappingCluster.#agents.set(wrappingJwk, new WeakRef(agent));
    }
    return agent;
  }

  static async wrap(
    wrappingJwk: JsonWebKey,
    cipherJwk: JsonWebKey
  ): Promise<ArrayBuffer> {
    const agent = WrappingCluster.#loadAgent(wrappingJwk);
    return await agent.wrap(cipherJwk);
  }
}
