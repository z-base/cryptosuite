import { toBufferSource } from "bytecodec";
import { assertEd25519PublicKey } from "../../.helpers/assertEd25519PublicKey.js";
import type { VerifyJWK } from "../../.types/jwk.js";

export class VerifyAgent {
  private keyPromise: Promise<CryptoKey>;

  constructor(verificationJwk: VerifyJWK) {
    assertEd25519PublicKey(verificationJwk, "VerifyAgent");
    this.keyPromise = crypto.subtle.importKey(
      "jwk",
      verificationJwk,
      { name: "Ed25519" },
      false,
      ["verify"],
    );
  }

  async verify(bytes: Uint8Array, signature: ArrayBuffer): Promise<boolean> {
    const key = await this.keyPromise;
    return crypto.subtle.verify(
      "Ed25519",
      key,
      signature,
      toBufferSource(bytes),
    );
  }
}
