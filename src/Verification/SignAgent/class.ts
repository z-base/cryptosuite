import { toBufferSource } from "bytecodec";
import { assertEd25519PrivateKey } from "../../.helpers/assertEd25519PrivateKey.js";
import type { SignJWK } from "../../.types/jwk.js";

export class SignAgent {
  private keyPromise: Promise<CryptoKey>;

  constructor(signingJwk: SignJWK) {
    assertEd25519PrivateKey(signingJwk, "SignAgent");
    this.keyPromise = crypto.subtle.importKey(
      "jwk",
      signingJwk,
      { name: "Ed25519" },
      false,
      ["sign"],
    );
  }

  async sign(bytes: Uint8Array): Promise<ArrayBuffer> {
    const key = await this.keyPromise;
    return crypto.subtle.sign("Ed25519", key, toBufferSource(bytes));
  }
}
