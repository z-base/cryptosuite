import assert from "node:assert/strict";
import test from "node:test";
import { performance } from "node:perf_hooks";
import { Bytes } from "bytecodec";
import {
  generateKeyset,
  SigningAgent,
  VerificationAgent,
  CipherAgent,
  CipherCluster,
  SigningCluster,
  VerificationCluster,
  WrappingAgent,
  UnwrappingAgent,
  WrappingCluster,
  UnwrappingCluster,
} from "./dist/index.js";

const PLAINTEXT = "mustan kissan paksut posket";
const plainBytes = Bytes.fromString(PLAINTEXT);

const keyset = await generateKeyset();

test("generateKeyset produces AES-GCM, ECDSA, and RSA keys", () => {
  assert.equal(keyset.cipherJwk.kty, "oct");
  assert.equal(keyset.signingJwk.kty, "EC");
  assert.equal(keyset.verificationJwk.kty, "EC");
  assert.equal(keyset.wrappingJwk.kty, "RSA");
  assert.equal(keyset.unwrappingJwk.kty, "RSA");
  assert.ok(keyset.cipherJwk.k, "AES key material missing");
});

test("encrypt/decrypt round trip", async () => {
  const cipherAgent = new CipherAgent(keyset.cipherJwk);
  const encrypted = await cipherAgent.encrypt(plainBytes);
  const decrypted = await cipherAgent.decrypt(encrypted);
  assert.equal(Bytes.toString(decrypted), PLAINTEXT);
});

test("sign/verify ciphertext integrity", async () => {
  const cipherAgent = new CipherAgent(keyset.cipherJwk);
  const signingAgent = new SigningAgent(keyset.signingJwk);
  const verificationAgent = new VerificationAgent(keyset.verificationJwk);

  const payload = await cipherAgent.encrypt(plainBytes);
  const ciphertextBytes = new Uint8Array(payload.ciphertext);
  const signature = await signingAgent.sign(ciphertextBytes);

  const authorized = await verificationAgent.verify(
    ciphertextBytes,
    signature
  );
  assert.equal(authorized, true);

  const tampered = new Uint8Array(payload.ciphertext.slice(0));
  tampered[0] ^= 1;
  const shouldFail = await verificationAgent.verify(tampered, signature);
  assert.equal(shouldFail, false);

  const decrypted = await cipherAgent.decrypt(payload);
  assert.equal(Bytes.toString(decrypted), PLAINTEXT);
});

test("CipherCluster encrypt/decrypt round trip", async () => {
  const resource = {
    id: "resource-1",
    kind: "note",
    body: PLAINTEXT,
    count: 3,
  };
  const artifact = await CipherCluster.encrypt(keyset.cipherJwk, resource);
  assert.equal(artifact.ciphertext instanceof ArrayBuffer, true);
  assert.equal(artifact.iv instanceof Uint8Array, true);

  const decrypted = await CipherCluster.decrypt(keyset.cipherJwk, artifact);
  assert.equal(decrypted.id, resource.id);
  assert.equal(decrypted.kind, resource.kind);
  assert.equal(decrypted.body, resource.body);
  assert.equal(decrypted.count, resource.count);
});

test("SigningCluster/VerificationCluster sign and verify JSON values", async () => {
  const value = { id: "resource-1", action: "read", nonce: 1 };
  const signature = await SigningCluster.sign(keyset.signingJwk, value);
  assert.equal(signature instanceof ArrayBuffer, true);

  const authorized = await VerificationCluster.verify(
    keyset.verificationJwk,
    value,
    signature
  );
  assert.equal(authorized, true);

  const tampered = { ...value, nonce: 2 };
  const shouldFail = await VerificationCluster.verify(
    keyset.verificationJwk,
    tampered,
    signature
  );
  assert.equal(shouldFail, false);
});

test("WrappingCluster/UnwrappingCluster wrap and unwrap cipher keys", async () => {
  const wrapped = await WrappingCluster.wrap(
    keyset.wrappingJwk,
    keyset.cipherJwk
  );
  const unwrapped = await UnwrappingCluster.unwrap(
    keyset.unwrappingJwk,
    wrapped
  );
  assert.equal(unwrapped.kty, "oct");
  assert.equal(unwrapped.k, keyset.cipherJwk.k);
});

test("WrappingAgent/UnwrappingAgent wrap and unwrap cipher keys", async () => {
  const wrapper = new WrappingAgent(keyset.wrappingJwk);
  const unwrapper = new UnwrappingAgent(keyset.unwrappingJwk);
  const wrapped = await wrapper.wrap(keyset.cipherJwk);
  const unwrapped = await unwrapper.unwrap(wrapped);
  assert.equal(unwrapped.kty, "oct");
  assert.equal(unwrapped.k, keyset.cipherJwk.k);
});

function formatOps(durationMs, iterations) {
  const opsPerSec = iterations / (durationMs / 1000);
  return `${durationMs.toFixed(2)}ms (${opsPerSec.toFixed(1)} ops/sec)`;
}

async function runBenchmark(iterations = 200) {
  const cipherAgent = new CipherAgent(keyset.cipherJwk);
  const signingAgent = new SigningAgent(keyset.signingJwk);
  const verificationAgent = new VerificationAgent(keyset.verificationJwk);

  const encryptStart = performance.now();
  for (let i = 0; i < iterations; i++) {
    await cipherAgent.encrypt(plainBytes);
  }
  const encryptDuration = performance.now() - encryptStart;

  const fullStart = performance.now();
  for (let i = 0; i < iterations; i++) {
    const payload = await cipherAgent.encrypt(plainBytes);
    const ciphertextBytes = new Uint8Array(payload.ciphertext);
    const signature = await signingAgent.sign(ciphertextBytes);
    await verificationAgent.verify(ciphertextBytes, signature);
    await cipherAgent.decrypt(payload);
  }
  const fullDuration = performance.now() - fullStart;

  return {
    encryptDuration,
    fullDuration,
    iterations,
  };
}

const shouldBenchmark =
  process.env.BENCHMARK === "1" ||
  process.env.BENCHMARK?.toLowerCase() === "true" ||
  process.argv.includes("--bench");

const iterationsFlag = process.argv
  .find((arg) => arg.startsWith("--iterations="))
  ?.split("=")[1];

const parsedIterations = iterationsFlag ? Number(iterationsFlag) : undefined;
const benchmarkIterations =
  Number.isFinite(parsedIterations) && parsedIterations > 0
    ? parsedIterations
    : 200;

test(
  "benchmark encrypt/sign/verify/decrypt",
  { skip: !shouldBenchmark },
  async (t) => {
    const { encryptDuration, fullDuration, iterations } = await runBenchmark(
      benchmarkIterations
    );
    t.diagnostic(`encrypt only: ${formatOps(encryptDuration, iterations)}`);
    t.diagnostic(`full pipeline: ${formatOps(fullDuration, iterations)}`);
  }
);
