# Zeyra

Client-side WebCrypto helpers for AES-GCM encryption, ECDSA signatures, and RSA-OAEP key wrapping, with byte-oriented cluster helpers.

## Compatibility

- WebCrypto (`crypto.subtle`) is stable in evergreen browsers; unprefixed support shipped in Chrome 37 (2014), Firefox 34 (2014), Edge 12 (2015), and Safari 11 (2017).
- Zeyra relies on AES-GCM, ECDSA P-256, and RSA-OAEP plus wrap/unwrap; legacy EdgeHTML/IE have partial WebCrypto (notably missing ECDSA), so target Chromium Edge (79+, 2020) and modern browsers.
- ESM only; requires global `crypto.subtle`.

## Features

- AES-GCM 256 encryption/decryption via `CipherAgent` and `CipherCluster`
- ECDSA P-256 sign/verify via `SigningAgent`, `VerificationAgent`, and clusters
- RSA-OAEP 4096 wrap/unwrap for AES-GCM JWKs
- `generateKeyset()` yields `cipherJwk`, `signingJwk`, `verificationJwk`, `wrappingJwk`, `unwrappingJwk`
- Cluster classes cache agents with `WeakRef`; they are a lightweight optimization, not a full end-to-end solution
- Byte-oriented clusters return raw `Uint8Array` / `ArrayBuffer` (no base64); use `bytecodec` for JSON, compression, and encoding
- TypeScript source; published package ships compiled JS + `.d.ts`

## Requirements

- Node.js 18+ for server/edge usage
- ESM environment (`"type": "module"`)
- `bytecodec` for JSON/bytes/compression helpers

## Installation

```sh
npm install zeyra
# or
pnpm add zeyra
# or
yarn add zeyra
```

## Quickstart (agents)

```js
import { Bytes } from "bytecodec";
import {
  generateKeyset,
  CipherAgent,
  SigningAgent,
  VerificationAgent,
} from "zeyra";

const { cipherJwk, signingJwk, verificationJwk } = await generateKeyset();

const cipher = new CipherAgent(cipherJwk);
const signer = new SigningAgent(signingJwk);
const verifier = new VerificationAgent(verificationJwk);

const payload = await cipher.encrypt(Bytes.fromString("hello world"));
const ciphertextBytes = new Uint8Array(payload.ciphertext);
const signature = await signer.sign(ciphertextBytes);

const authorized = await verifier.verify(ciphertextBytes, signature);
const plaintext = Bytes.toString(await cipher.decrypt(payload));
```

## Managed cluster flow

```js
import {
  generateKeyset,
  CipherCluster,
  SigningCluster,
  VerificationCluster,
} from "zeyra";

const { cipherJwk, signingJwk, verificationJwk } = await generateKeyset();

const resource = { id: "file-123", body: "hello world" };
const artifact = await CipherCluster.encrypt(cipherJwk, resource);
// artifact: { iv: Uint8Array, ciphertext: ArrayBuffer }

const signature = await SigningCluster.sign(signingJwk, resource.id);
const authorized = await VerificationCluster.verify(
  verificationJwk,
  resource.id,
  signature
);

const decrypted = await CipherCluster.decrypt(cipherJwk, artifact);
```

## Key wrapping flow

```js
import { generateKeyset, WrappingCluster, UnwrappingCluster } from "zeyra";

const { cipherJwk, wrappingJwk, unwrappingJwk } = await generateKeyset();

const wrapped = await WrappingCluster.wrap(wrappingJwk, cipherJwk);
const unwrappedCipherJwk = await UnwrappingCluster.unwrap(
  unwrappingJwk,
  wrapped
);
```

## API

- `generateKeyset()` -> `{ cipherJwk, verificationJwk, signingJwk, wrappingJwk, unwrappingJwk }`
- `new CipherAgent(cipherJwk)`
  - `.encrypt(Uint8Array)` -> `{ iv: Uint8Array, ciphertext: ArrayBuffer }`
  - `.decrypt({ iv, ciphertext })` -> `Uint8Array`
- `new SigningAgent(signingJwk)`
  - `.sign(Uint8Array)` -> `ArrayBuffer` (ECDSA P-256 / SHA-256)
- `new VerificationAgent(verificationJwk)`
  - `.verify(Uint8Array, ArrayBuffer)` -> `boolean`
- `new WrappingAgent(wrappingJwk)`
  - `.wrap(cipherJwk)` -> `ArrayBuffer` (RSA-OAEP / SHA-256)
- `new UnwrappingAgent(unwrappingJwk)`
  - `.unwrap(ArrayBuffer)` -> `JsonWebKey`
- `CipherCluster.encrypt(cipherJwk, resource)` -> `{ iv, ciphertext }`
- `CipherCluster.decrypt(cipherJwk, artifact)` -> `resource`
- `SigningCluster.sign(signingJwk, value)` -> `ArrayBuffer`
- `VerificationCluster.verify(verificationJwk, value, signature)` -> `boolean`
- `WrappingCluster.wrap(wrappingJwk, cipherJwk)` -> `ArrayBuffer`
- `UnwrappingCluster.unwrap(unwrappingJwk, wrapped)` -> `JsonWebKey`

## Serialization helpers

Zeyra keeps clusters byte-oriented. Use `bytecodec` when you need to serialize or store artifacts.

```js
import { Bytes } from "bytecodec";

const artifact = await CipherCluster.encrypt(cipherJwk, resource);
const ciphertextB64 = Bytes.toBase64UrlString(
  new Uint8Array(artifact.ciphertext)
);
const ivB64 = Bytes.toBase64UrlString(artifact.iv);
```

## Testing and benchmarks

- Build: `npm run build` (outputs `dist/`)
- Run tests: `npm test` (builds `dist/`, then runs `node --test`)
- Run benchmarks: `npm run bench`
  - Pass iterations: `npm run bench -- --iterations=500`

## Benchmarks (local)

Results will vary by hardware, runtime, and payload size. Run `npm run bench` to reproduce.

- Node v22.14.0 (Windows), iterations=200
  - encrypt only: 44.68ms (4476.3 ops/sec)
  - full pipeline: 115.15ms (1736.9 ops/sec)

## Notes

- Zeyra is intended for client-side encryption workflows; server/edge usage is supported where WebCrypto is available.
- Cluster helpers cache keys with `WeakRef` and keep `CryptoKey` material private inside agents.
- `CipherCluster` compresses JSON payloads before encryption; `SigningCluster`/`VerificationCluster` sign JSON values.

## License

MIT
