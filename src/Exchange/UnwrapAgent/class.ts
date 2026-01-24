import { assertAesGcm256Key } from "../../.helpers/assertAesGcm256Key.js";
import { assertRsaOaep4096PrivateKey } from "../../.helpers/assertRsaOaep4096PrivateKey.js";
import type { CipherJWK, UnwrapJWK } from "../../.types/jwk.js";

export class UnwrapAgent {
  private keyPromise: Promise<CryptoKey>;
  constructor(unwrapJwk: UnwrapJWK) {
    assertRsaOaep4096PrivateKey(unwrapJwk, "UnwrapAgent");
    this.keyPromise = crypto.subtle.importKey(
      "jwk",
      unwrapJwk,
      { name: "RSA-OAEP", hash: "SHA-256" },
      false,
      ["unwrapKey"],
    );
  }

  async unwrap(wrapped: ArrayBuffer): Promise<CipherJWK> {
    const unwrappingKey = await this.keyPromise;

    const aesKey = await crypto.subtle.unwrapKey(
      "jwk",
      wrapped,
      unwrappingKey,
      { name: "RSA-OAEP" },
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt"],
    );

    const jwk = (await crypto.subtle.exportKey("jwk", aesKey)) as CipherJWK;
    assertAesGcm256Key(jwk, "UnwrapAgent.unwrap");
    return jwk;
  }
}
