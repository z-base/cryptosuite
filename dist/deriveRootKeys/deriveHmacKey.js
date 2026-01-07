export async function deriveHmacKey(first) {
    const key = await crypto.subtle.importKey("raw", first, { name: "HMAC", hash: "SHA-256" }, true, ["sign", "verify"]);
    return await crypto.subtle.exportKey("jwk", key);
}
//# sourceMappingURL=deriveHmacKey.js.map