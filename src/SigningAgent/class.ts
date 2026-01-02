import { Bytes } from "bytecodec";
export class SigningAgent {
  private keyPromise: Promise<CryptoKey>;

  constructor(signingJwk: JsonWebKey) {
    this.keyPromise = crypto.subtle.importKey(
      "jwk",
      signingJwk,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["sign"]
    );
  }

  async sign(bytes: Uint8Array): Promise<ArrayBuffer> {
    const key = await this.keyPromise;
    return crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      key,
      Bytes.toBufferSource(bytes)
    );
  }
}
