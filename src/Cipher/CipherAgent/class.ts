import { toBufferSource } from "bytecodec";
import { assertAesGcm256Key } from "../../.helpers/assertAesGcm256Key.js";
import { assertAesGcmIv96 } from "../../.helpers/assertAesGcmIv96.js";
import type { CipherJWK } from "../../.types/jwk.js";
export class CipherAgent {
  private keyPromise: Promise<CryptoKey>;
  constructor(cipherJwk: CipherJWK) {
    assertAesGcm256Key(cipherJwk, "CipherAgent");
    this.keyPromise = crypto.subtle.importKey(
      "jwk",
      cipherJwk,
      { name: "AES-GCM" },
      false,
      ["encrypt", "decrypt"],
    );
  }

  async encrypt(
    plaintext: Uint8Array,
  ): Promise<{ iv: Uint8Array; ciphertext: ArrayBuffer }> {
    const key = await this.keyPromise;
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      key,
      toBufferSource(plaintext),
    );
    return { iv, ciphertext };
  }

  async decrypt({
    iv,
    ciphertext,
  }: {
    iv: Uint8Array<ArrayBufferLike>;
    ciphertext: ArrayBuffer;
  }): Promise<Uint8Array> {
    const key = await this.keyPromise;
    assertAesGcmIv96(iv, "CipherAgent.decrypt");
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: toBufferSource(iv) },
      key,
      ciphertext,
    );
    return new Uint8Array(plaintext);
  }
}
