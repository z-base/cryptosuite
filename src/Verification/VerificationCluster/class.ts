import { fromJSON } from "bytecodec";
import { VerifyAgent } from "../VerifyAgent/class.js";
import { SignAgent } from "../SignAgent/class.js";
import type { SignJWK, VerifyJWK } from "../../.types/jwk.js";

export type VerificationAgentType = "sign" | "verify";
export type VerificationAgentByType = {
  sign: SignAgent;
  verify: VerifyAgent;
};

export class VerificationCluster {
  static #signAgents = new WeakMap<SignJWK, WeakRef<SignAgent>>();
  static #verifyAgents = new WeakMap<VerifyJWK, WeakRef<VerifyAgent>>();

  static #loadSignAgent(signingJwk: SignJWK): SignAgent {
    const weakRef = VerificationCluster.#signAgents.get(signingJwk);
    let agent = weakRef?.deref();
    if (!agent) {
      agent = new SignAgent(signingJwk);
      VerificationCluster.#signAgents.set(signingJwk, new WeakRef(agent));
    }
    return agent;
  }

  static #loadVerifyAgent(verificationJwk: VerifyJWK): VerifyAgent {
    const weakRef = VerificationCluster.#verifyAgents.get(verificationJwk);
    let agent = weakRef?.deref();
    if (!agent) {
      agent = new VerifyAgent(verificationJwk);
      VerificationCluster.#verifyAgents.set(verificationJwk, new WeakRef(agent));
    }
    return agent;
  }

  static async sign(signingJwk: SignJWK, value: any): Promise<ArrayBuffer> {
    const agent = VerificationCluster.#loadSignAgent(signingJwk);
    const bytes = fromJSON(value);
    return await agent.sign(bytes);
  }

  static async verify(
    verificationJwk: VerifyJWK,
    value: any,
    signature: ArrayBuffer,
  ): Promise<boolean> {
    const agent = VerificationCluster.#loadVerifyAgent(verificationJwk);
    const valueBytes = fromJSON(value);
    return await agent.verify(valueBytes, signature);
  }
}
