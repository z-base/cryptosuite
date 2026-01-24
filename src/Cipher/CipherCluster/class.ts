import { fromJSON, toJSON, fromCompressed, toCompressed } from "bytecodec";
import { CipherAgent } from "../CipherAgent/class.js";
import type { CipherJWK } from "../../.types/jwk.js";

export class CipherCluster {
  static #agents = new WeakMap<CipherJWK, WeakRef<CipherAgent>>();

  static #loadAgent(cipherJwk: CipherJWK): CipherAgent {
    const weakRef = CipherCluster.#agents.get(cipherJwk);
    let agent = weakRef?.deref();
    if (!agent) {
      agent = new CipherAgent(cipherJwk);
      CipherCluster.#agents.set(cipherJwk, new WeakRef(agent));
    }
    return agent;
  }

  static async encrypt(
    cipherJwk: CipherJWK,
    resource: any,
  ): Promise<{ iv: Uint8Array; ciphertext: ArrayBuffer }> {
    const agent = CipherCluster.#loadAgent(cipherJwk);
    const bytes = fromJSON(resource);

    const compressed = await toCompressed(bytes);
    return await agent.encrypt(compressed);
  }

  static async decrypt(
    cipherJwk: CipherJWK,
    artifact: { iv: Uint8Array; ciphertext: ArrayBuffer },
  ): Promise<any> {
    const agent = CipherCluster.#loadAgent(cipherJwk);
    const bytes = await agent.decrypt(artifact);
    const decompressed = await fromCompressed(bytes);
    return toJSON(decompressed);
  }
}
