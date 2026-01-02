import { Bytes } from "bytecodec";

export class VerificationAgent {
  private keyPromise: Promise<CryptoKey>;

  constructor(verificationJwk: JsonWebKey) {
    this.keyPromise = crypto.subtle.importKey(
      "jwk",
      verificationJwk,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"]
    );
  }

  async verify(bytes: Uint8Array, signature: ArrayBuffer): Promise<boolean> {
    const key = await this.keyPromise;
    return crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      key,
      signature,
      Bytes.toBufferSource(bytes)
    );
  }
}
