export declare class HmacAgent {
    private keyPromise;
    constructor(hmacJwk: JsonWebKey);
    sign(challenge: BufferSource): Promise<ArrayBuffer>;
    verify(challenge: BufferSource, signature: BufferSource): Promise<boolean>;
}
//# sourceMappingURL=class.d.ts.map