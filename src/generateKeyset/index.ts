export async function generateKeyset(): Promise<{
  cipherJwk: JsonWebKey;
  verificationJwk: JsonWebKey;
  signingJwk: JsonWebKey;
  wrappingJwk: JsonWebKey;
  unwrappingJwk: JsonWebKey;
}> {
  const aesKey = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
  const cipherJwk = await crypto.subtle.exportKey("jwk", aesKey);

  const signPair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"]
  );
  const verificationJwk = await crypto.subtle.exportKey(
    "jwk",
    signPair.publicKey
  );
  const signingJwk = await crypto.subtle.exportKey("jwk", signPair.privateKey);

  const wrapPair = await crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 4096,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["wrapKey", "unwrapKey"]
  );
  const wrappingJwk = await crypto.subtle.exportKey("jwk", wrapPair.publicKey);
  const unwrappingJwk = await crypto.subtle.exportKey(
    "jwk",
    wrapPair.privateKey
  );

  return {
    cipherJwk,
    verificationJwk,
    signingJwk,
    wrappingJwk,
    unwrappingJwk,
  };
}
