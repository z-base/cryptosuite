import { Bytes } from "bytecodec";
import { VerificationAgent } from "../VerificationAgent/class.js";

export class VerificationCluster {
  static #agents = new WeakMap<JsonWebKey, WeakRef<VerificationAgent>>();

  static #loadAgent(verificationJwk: JsonWebKey): VerificationAgent {
    const weakRef = VerificationCluster.#agents.get(verificationJwk);
    let agent = weakRef?.deref();
    if (!agent) {
      agent = new VerificationAgent(verificationJwk);
      VerificationCluster.#agents.set(verificationJwk, new WeakRef(agent));
    }
    return agent;
  }

  static async verify(
    verificationJwk: JsonWebKey,
    value: any,
    signature: ArrayBuffer
  ): Promise<boolean> {
    const agent = VerificationCluster.#loadAgent(verificationJwk);
    const valueBytes = Bytes.fromJSON(value);
    return await agent.verify(valueBytes, signature);
  }
}
