import { performance } from 'node:perf_hooks'
import {
  generateCipherKey,
  CipherAgent,
  generateHMACKey,
  HMACAgent,
  generateVerificationPair,
  SignAgent,
  VerifyAgent,
  generateExchangePair,
  WrapAgent,
  UnwrapAgent,
} from '../dist/index.js'

const iterationsArg = process.argv.find((arg) =>
  arg.startsWith('--iterations=')
)
const iterations = iterationsArg ? Number(iterationsArg.split('=')[1]) : 200

function formatOps(durationMs, count) {
  const opsPerSec = count / (durationMs / 1000)
  return `${durationMs.toFixed(2)}ms (${opsPerSec.toFixed(1)} ops/sec)`
}

async function benchAes() {
  const cipherJwk = await generateCipherKey()
  const agent = new CipherAgent(cipherJwk)
  const payload = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8])

  const start = performance.now()
  for (let i = 0; i < iterations; i += 1) {
    await agent.encrypt(payload)
  }
  const duration = performance.now() - start
  console.log(`AES-GCM encrypt: ${formatOps(duration, iterations)}`)
}

async function benchHmac() {
  const hmacJwk = await generateHMACKey()
  const agent = new HMACAgent(hmacJwk)
  const payload = new Uint8Array([9, 9, 9, 9, 9])

  const start = performance.now()
  for (let i = 0; i < iterations; i += 1) {
    const sig = await agent.sign(payload)
    await agent.verify(payload, sig)
  }
  const duration = performance.now() - start
  console.log(`HMAC sign+verify: ${formatOps(duration, iterations)}`)
}

async function benchEd25519() {
  try {
    const { signJwk, verifyJwk } = await generateVerificationPair()
    const signer = new SignAgent(signJwk)
    const verifier = new VerifyAgent(verifyJwk)
    const payload = new Uint8Array([5, 4, 3, 2, 1])

    const start = performance.now()
    for (let i = 0; i < iterations; i += 1) {
      const sig = await signer.sign(payload)
      await verifier.verify(payload, sig)
    }
    const duration = performance.now() - start
    console.log(`Ed25519 sign+verify: ${formatOps(duration, iterations)}`)
  } catch (err) {
    console.log(`Ed25519 sign+verify: skipped (${err?.code ?? 'unsupported'})`)
  }
}

async function benchRsaWrap() {
  try {
    const { wrapJwk, unwrapJwk } = await generateExchangePair()
    const cipherJwk = await generateCipherKey()
    const wrapper = new WrapAgent(wrapJwk)
    const unwrapper = new UnwrapAgent(unwrapJwk)

    const start = performance.now()
    for (let i = 0; i < iterations; i += 1) {
      const wrapped = await wrapper.wrap(cipherJwk)
      await unwrapper.unwrap(wrapped)
    }
    const duration = performance.now() - start
    console.log(`RSA-OAEP wrap+unwrap: ${formatOps(duration, iterations)}`)
  } catch (err) {
    console.log(`RSA-OAEP wrap+unwrap: skipped (${err?.code ?? 'unsupported'})`)
  }
}

await benchAes()
await benchHmac()
await benchEd25519()
await benchRsaWrap()
