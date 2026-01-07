export async function deriveCipherKey(second) {
    const key = await crypto.subtle.importKey("raw", second, { name: "AES-GCM" }, true, ["encrypt", "decrypt"]);
    return await crypto.subtle.exportKey("jwk", key);
}
//# sourceMappingURL=deriveCipherKey.js.map