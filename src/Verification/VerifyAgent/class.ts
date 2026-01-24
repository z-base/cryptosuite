import { toBufferSource } from "bytecodec";
import { assertEcdsaP256PublicKey } from "../../.helpers/assertEcdsaP256PublicKey.js";
import type { VerifyJWK } from "../../.types/jwk.js";

export class VerifyAgent {
  private keyPromise: Promise<CryptoKey>;

  constructor(verificationJwk: VerifyJWK) {
    assertEcdsaP256PublicKey(verificationJwk, "VerifyAgent");
    this.keyPromise = crypto.subtle.importKey(
      "jwk",
      verificationJwk,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
  }

  async verify(bytes: Uint8Array, signature: ArrayBuffer): Promise<boolean> {
    const key = await this.keyPromise;
    return crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      key,
      signature,
      toBufferSource(bytes),
    );
  }
}
