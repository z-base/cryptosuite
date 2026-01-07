export async function generateCipherKey() {
    const aesKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
    return await crypto.subtle.exportKey("jwk", aesKey);
}
//# sourceMappingURL=index.js.map