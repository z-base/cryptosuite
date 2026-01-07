export type RootKeys = {
    hmacJwk: JsonWebKey;
    cipherJwk: JsonWebKey;
};
export declare function deriveRootKeys(prfResults: AuthenticationExtensionsPRFOutputs["results"] | undefined): Promise<RootKeys | false>;
//# sourceMappingURL=index.d.ts.map