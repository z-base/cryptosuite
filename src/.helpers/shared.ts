export const BYTES_32 = 32
export const USE_SIG = 'sig'
export const USE_ENC = 'enc'

export const AES_GCM_ALG = 'A256GCM'
export const AES_GCM_USE = USE_ENC
export const AES_GCM_KEY_BYTES = BYTES_32
export const AES_GCM_KEY_OPS = ['encrypt', 'decrypt'] as const
export const AES_GCM_IV_BYTES = 12

export const ED25519_ALG = 'EdDSA'
export const ED25519_CURVE = 'Ed25519'
export const ED25519_USE = USE_SIG
export const ED25519_BYTES = BYTES_32
export const ED25519_PRIVATE_OPS = ['sign'] as const
export const ED25519_PUBLIC_OPS = ['verify'] as const

export const HMAC_ALG = 'HS256'
export const HMAC_USE = USE_SIG
export const HMAC_KEY_BYTES = BYTES_32
export const HMAC_KEY_OPS = ['sign', 'verify'] as const

export const RSA_OAEP_ALG = 'RSA-OAEP-256'
export const RSA_OAEP_USE = USE_ENC
export const RSA_MODULUS_BYTES = 512
export const RSA_PRIVATE_OPS = ['unwrapKey', 'decrypt'] as const
export const RSA_PUBLIC_OPS = ['wrapKey', 'encrypt'] as const
