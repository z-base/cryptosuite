export declare class VerificationAgent {
    private keyPromise;
    constructor(verificationJwk: JsonWebKey);
    verify(bytes: Uint8Array, signature: ArrayBuffer): Promise<boolean>;
}
//# sourceMappingURL=class.d.ts.map