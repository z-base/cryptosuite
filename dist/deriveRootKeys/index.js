// deriveRootKeys.ts
import { deriveCipherKey } from "./deriveCipherKey.js";
import { deriveHmacKey } from "./deriveHmacKey.js";
function isArrayBuffer(value) {
    return value instanceof ArrayBuffer;
}
export async function deriveRootKeys(prfResults) {
    if (!prfResults)
        return false;
    const { first, second } = prfResults;
    if (!isArrayBuffer(first) || !isArrayBuffer(second))
        return false;
    const firstHash = await crypto.subtle.digest("SHA-256", first);
    const secondHash = await crypto.subtle.digest("SHA-256", second);
    const [hmacJwk, cipherJwk] = await Promise.all([
        deriveHmacKey(firstHash),
        deriveCipherKey(secondHash),
    ]);
    return { hmacJwk, cipherJwk };
}
//# sourceMappingURL=index.js.map