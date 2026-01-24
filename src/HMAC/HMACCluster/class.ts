import { toBufferSource, fromJSON } from "bytecodec";
import { HMACAgent } from "../HMACAgent/class.js";
import type { HMACJWK } from "../../.types/jwk.js";

export class HMACCluster {
  static #agents = new WeakMap<HMACJWK, WeakRef<HMACAgent>>();

  static #loadAgent(hmacJwk: HMACJWK): HMACAgent {
    const weakRef = HMACCluster.#agents.get(hmacJwk);
    let agent = weakRef?.deref();
    if (!agent) {
      agent = new HMACAgent(hmacJwk);
      HMACCluster.#agents.set(hmacJwk, new WeakRef(agent));
    }
    return agent;
  }

  static async sign(hmacJwk: HMACJWK, value: any): Promise<ArrayBuffer> {
    const agent = HMACCluster.#loadAgent(hmacJwk);
    const bytes = toBufferSource(fromJSON(value));
    return await agent.sign(bytes);
  }

  static async verify(
    hmacJwk: HMACJWK,
    value: any,
    signature: ArrayBuffer,
  ): Promise<boolean> {
    const agent = HMACCluster.#loadAgent(hmacJwk);
    const bytes = toBufferSource(fromJSON(value));
    return await agent.verify(bytes, signature);
  }
}
