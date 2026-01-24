import { toBufferSource } from "bytecodec";
import { assertEcdsaP256PrivateKey } from "../../.helpers/assertEcdsaP256PrivateKey.js";
import type { SignJWK } from "../../.types/jwk.js";

export class SignAgent {
  private keyPromise: Promise<CryptoKey>;

  constructor(signingJwk: SignJWK) {
    assertEcdsaP256PrivateKey(signingJwk, "SignAgent");
    this.keyPromise = crypto.subtle.importKey(
      "jwk",
      signingJwk,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["sign"],
    );
  }

  async sign(bytes: Uint8Array): Promise<ArrayBuffer> {
    const key = await this.keyPromise;
    return crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      key,
      toBufferSource(bytes),
    );
  }
}
