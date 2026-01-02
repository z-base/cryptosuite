import { Bytes } from "bytecodec";
import { SigningAgent } from "../SigningAgent/class.js";

export class SigningCluster {
  static #agents = new WeakMap<JsonWebKey, WeakRef<SigningAgent>>();

  static #loadAgent(signingJwk: JsonWebKey): SigningAgent {
    const weakRef = SigningCluster.#agents.get(signingJwk);
    let agent = weakRef?.deref();
    if (!agent) {
      agent = new SigningAgent(signingJwk);
      SigningCluster.#agents.set(signingJwk, new WeakRef(agent));
    }
    return agent;
  }

  static async sign(signingJwk: JsonWebKey, value: any): Promise<ArrayBuffer> {
    const agent = SigningCluster.#loadAgent(signingJwk);
    const bytes = Bytes.fromJSON(value);
    return await agent.sign(bytes);
  }
}
