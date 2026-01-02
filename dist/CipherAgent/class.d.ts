export declare class CipherAgent {
    private keyPromise;
    constructor(cipherJwk: JsonWebKey);
    encrypt(plaintext: Uint8Array): Promise<{
        iv: Uint8Array;
        ciphertext: ArrayBuffer;
    }>;
    decrypt({ iv, ciphertext, }: {
        iv: Uint8Array<ArrayBufferLike>;
        ciphertext: ArrayBuffer;
    }): Promise<Uint8Array>;
}
//# sourceMappingURL=class.d.ts.map