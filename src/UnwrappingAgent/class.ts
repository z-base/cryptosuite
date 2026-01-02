export class UnwrappingAgent {
  private keyPromise: Promise<CryptoKey>;
  constructor(unwrappingJwk: JsonWebKey) {
    this.keyPromise = crypto.subtle.importKey(
      "jwk",
      unwrappingJwk,
      { name: "RSA-OAEP", hash: "SHA-256" },
      false,
      ["unwrapKey"]
    );
  }

  async unwrap(wrapped: ArrayBuffer): Promise<JsonWebKey> {
    const unwrappingKey = await this.keyPromise;

    const aesKey = await crypto.subtle.unwrapKey(
      "jwk",
      wrapped,
      unwrappingKey,
      { name: "RSA-OAEP" },
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt"]
    );

    return crypto.subtle.exportKey("jwk", aesKey);
  }
}
