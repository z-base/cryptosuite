export declare class CipherCluster {
    #private;
    static encrypt(cipherJwk: JsonWebKey, resource: any): Promise<{
        iv: Uint8Array;
        ciphertext: ArrayBuffer;
    }>;
    static decrypt(cipherJwk: JsonWebKey, artifact: {
        iv: Uint8Array;
        ciphertext: ArrayBuffer;
    }): Promise<any>;
}
//# sourceMappingURL=class.d.ts.map