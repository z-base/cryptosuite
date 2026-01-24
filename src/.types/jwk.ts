export type CipherJWK = JsonWebKey & {
  kty: "oct";
  k: string;
  alg?: "A256GCM";
  use?: "enc";
  key_ops?: ("encrypt" | "decrypt")[];
};

export type HMACJWK = JsonWebKey & {
  kty: "oct";
  k: string;
  alg?: "HS256";
  use?: "sig";
  key_ops?: ("sign" | "verify")[];
};

export type WrapJWK = JsonWebKey & {
  kty: "RSA";
  n: string;
  e: string;
  alg?: "RSA-OAEP-256";
  use?: "enc";
  key_ops?: ("wrapKey" | "encrypt")[];
  d?: never;
  p?: never;
  q?: never;
  dp?: never;
  dq?: never;
  qi?: never;
};

export type UnwrapJWK = JsonWebKey & {
  kty: "RSA";
  n: string;
  e: string;
  d: string;
  p?: string;
  q?: string;
  dp?: string;
  dq?: string;
  qi?: string;
  alg?: "RSA-OAEP-256";
  use?: "enc";
  key_ops?: ("unwrapKey" | "decrypt")[];
};

export type SignJWK = JsonWebKey & {
  kty: "EC";
  crv: "P-256";
  x: string;
  y: string;
  d: string;
  alg?: "ES256";
  use?: "sig";
  key_ops?: ("sign")[];
};

export type VerifyJWK = JsonWebKey & {
  kty: "EC";
  crv: "P-256";
  x: string;
  y: string;
  alg?: "ES256";
  use?: "sig";
  key_ops?: ("verify")[];
  d?: never;
};
