import { assertAesGcm256Key } from "../../.helpers/assertAesGcm256Key.js";
import { assertRsaOaep4096PublicKey } from "../../.helpers/assertRsaOaep4096PublicKey.js";
import type { CipherJWK, WrapJWK } from "../../.types/jwk.js";

export class WrapAgent {
  private keyPromise: Promise<CryptoKey>;
  constructor(wrapJwk: WrapJWK) {
    assertRsaOaep4096PublicKey(wrapJwk, "WrapAgent");
    this.keyPromise = crypto.subtle.importKey(
      "jwk",
      wrapJwk,
      { name: "RSA-OAEP", hash: "SHA-256" },
      false,
      ["wrapKey"],
    );
  }

  async wrap(cipherJwk: CipherJWK): Promise<ArrayBuffer> {
    assertAesGcm256Key(cipherJwk, "WrapAgent.wrap");
    const wrappingKey = await this.keyPromise;

    const aesKey = await crypto.subtle.importKey(
      "jwk",
      cipherJwk,
      { name: "AES-GCM" },
      true,
      ["encrypt", "decrypt"],
    );

    return crypto.subtle.wrapKey("jwk", aesKey, wrappingKey, {
      name: "RSA-OAEP",
    });
  }
}
