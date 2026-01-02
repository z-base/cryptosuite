export declare class SigningAgent {
    private keyPromise;
    constructor(signingJwk: JsonWebKey);
    sign(bytes: Uint8Array): Promise<ArrayBuffer>;
}
//# sourceMappingURL=class.d.ts.map