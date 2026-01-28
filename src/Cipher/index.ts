export { deriveCipherKey } from './deriveCipherKey/index.js'
export { generateCipherKey } from './generateCipherKey/index.js'
export { CipherAgent } from './CipherAgent/class.js'
export { CipherCluster } from './CipherCluster/class.js'
export type CipherJWK = JsonWebKey & {
  kty: 'oct'
  k: string
  alg?: 'A256GCM'
  use?: 'enc'
  key_ops?: ('encrypt' | 'decrypt')[]
}
