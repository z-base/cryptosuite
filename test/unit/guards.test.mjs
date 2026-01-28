import assert from "node:assert/strict";
import test from "node:test";
import { toBase64UrlString } from "@z-base/bytecodec";
import {
  generateCipherKey,
  deriveCipherKey,
  CipherAgent,
  generateHMACKey,
  deriveHMACKey,
  HMACAgent,
  generateVerificationPair,
  SignAgent,
  VerifyAgent,
  generateExchangePair,
  WrapAgent,
  UnwrapAgent,
  deriveOID,
} from "../../dist/index.js";
import { CryptosuiteError } from "../../dist/.errors/class.js";

const ORIGINAL_CRYPTO = globalThis.crypto;

function setCrypto(value) {
  Object.defineProperty(globalThis, "crypto", {
    value,
    configurable: true,
    writable: true,
  });
}

async function withCrypto(mock, fn) {
  setCrypto(mock);
  try {
    return await fn();
  } finally {
    if (ORIGINAL_CRYPTO === undefined) {
      delete globalThis.crypto;
    } else {
      setCrypto(ORIGINAL_CRYPTO);
    }
  }
}

async function expectCodeAsync(fn, code) {
  let threw = false;
  try {
    await fn();
  } catch (err) {
    threw = true;
    assert.ok(err instanceof CryptosuiteError);
    assert.equal(err.code, code);
  }
  assert.equal(threw, true);
}

function buildCrypto(overrides = {}) {
  const hasGetRandomValues = Object.prototype.hasOwnProperty.call(
    overrides,
    "getRandomValues",
  );
  const getRandomValues = hasGetRandomValues
    ? overrides.getRandomValues
    : (arr) => arr;

  const subtleOverrides = overrides.subtle ?? {};
  const subtle = {
    generateKey: async () => ({}),
    importKey: async () => ({}),
    wrapKey: async () => new ArrayBuffer(1),
    unwrapKey: async () => ({}),
    encrypt: async () => new ArrayBuffer(1),
    decrypt: async () => new ArrayBuffer(1),
    sign: async () => new ArrayBuffer(1),
    verify: async () => true,
    digest: async () => new ArrayBuffer(1),
    exportKey: async () => ({}),
    ...subtleOverrides,
  };

  return { getRandomValues, subtle };
}

const bytes32 = new Uint8Array(32).fill(5);
const b64_32 = toBase64UrlString(bytes32);
const rsaN = toBase64UrlString(new Uint8Array(512).fill(7));
const rsaE = toBase64UrlString(new Uint8Array([1, 0, 1]));

const cipherJwk = {
  kty: "oct",
  k: b64_32,
  alg: "A256GCM",
  use: "enc",
  key_ops: ["encrypt", "decrypt"],
};

const hmacJwk = {
  kty: "oct",
  k: b64_32,
  alg: "HS256",
  use: "sig",
  key_ops: ["sign", "verify"],
};

const signJwk = {
  kty: "OKP",
  crv: "Ed25519",
  x: b64_32,
  d: b64_32,
  alg: "EdDSA",
  use: "sig",
  key_ops: ["sign"],
};

const verifyJwk = {
  kty: "OKP",
  crv: "Ed25519",
  x: b64_32,
  alg: "EdDSA",
  use: "sig",
  key_ops: ["verify"],
};

const wrapJwk = {
  kty: "RSA",
  n: rsaN,
  e: rsaE,
  alg: "RSA-OAEP-256",
  use: "enc",
  key_ops: ["wrapKey"],
};

const unwrapJwk = {
  kty: "RSA",
  n: rsaN,
  e: rsaE,
  d: b64_32,
  alg: "RSA-OAEP-256",
  use: "enc",
  key_ops: ["unwrapKey"],
};

test("generateCipherKey maps unsupported AES-GCM", async () => {
  await withCrypto(
    buildCrypto({
      subtle: {
        generateKey: async () => {
          throw new Error("no");
        },
      },
    }),
    async () => {
      await expectCodeAsync(generateCipherKey, "AES_GCM_UNSUPPORTED");
    },
  );
});

test("deriveCipherKey maps unsupported AES-GCM", async () => {
  await withCrypto(
    buildCrypto({
      subtle: {
        importKey: async () => {
          throw new Error("no");
        },
      },
    }),
    async () => {
      await expectCodeAsync(() => deriveCipherKey(new Uint8Array(32)), "AES_GCM_UNSUPPORTED");
    },
  );
});

test("CipherAgent maps importKey failure", async () => {
  await withCrypto(
    buildCrypto({
      subtle: {
        importKey: async () => {
          throw new Error("no");
        },
      },
    }),
    async () => {
      const agent = new CipherAgent(cipherJwk);
      await expectCodeAsync(() => agent.encrypt(new Uint8Array([1])), "AES_GCM_UNSUPPORTED");
    },
  );
});

test("CipherAgent encrypt requires getRandomValues", async () => {
  await withCrypto(
    buildCrypto({
      getRandomValues: undefined,
    }),
    async () => {
      const agent = new CipherAgent(cipherJwk);
      await expectCodeAsync(() => agent.encrypt(new Uint8Array([1])), "GET_RANDOM_VALUES_UNAVAILABLE");
    },
  );
});

test("generateHMACKey maps unsupported HMAC", async () => {
  await withCrypto(
    buildCrypto({
      subtle: {
        generateKey: async () => {
          throw new Error("no");
        },
      },
    }),
    async () => {
      await expectCodeAsync(generateHMACKey, "HMAC_SHA256_UNSUPPORTED");
    },
  );
});

test("deriveHMACKey maps unsupported HMAC", async () => {
  await withCrypto(
    buildCrypto({
      subtle: {
        importKey: async () => {
          throw new Error("no");
        },
      },
    }),
    async () => {
      await expectCodeAsync(() => deriveHMACKey(new Uint8Array(32)), "HMAC_SHA256_UNSUPPORTED");
    },
  );
});

test("HMACAgent maps importKey failure", async () => {
  await withCrypto(
    buildCrypto({
      subtle: {
        importKey: async () => {
          throw new Error("no");
        },
      },
    }),
    async () => {
      const agent = new HMACAgent(hmacJwk);
      await expectCodeAsync(() => agent.sign(new Uint8Array([1])), "HMAC_SHA256_UNSUPPORTED");
    },
  );
});

test("generateVerificationPair maps unsupported Ed25519", async () => {
  await withCrypto(
    buildCrypto({
      subtle: {
        generateKey: async () => {
          throw new Error("no");
        },
      },
    }),
    async () => {
      await expectCodeAsync(generateVerificationPair, "ED25519_UNSUPPORTED");
    },
  );
});

test("SignAgent maps importKey failure", async () => {
  await withCrypto(
    buildCrypto({
      subtle: {
        importKey: async () => {
          throw new Error("no");
        },
      },
    }),
    async () => {
      const agent = new SignAgent(signJwk);
      await expectCodeAsync(() => agent.sign(new Uint8Array([1])), "ED25519_UNSUPPORTED");
    },
  );
});

test("VerifyAgent maps importKey failure", async () => {
  await withCrypto(
    buildCrypto({
      subtle: {
        importKey: async () => {
          throw new Error("no");
        },
      },
    }),
    async () => {
      const agent = new VerifyAgent(verifyJwk);
      await expectCodeAsync(() => agent.verify(new Uint8Array([1]), new ArrayBuffer(1)), "ED25519_UNSUPPORTED");
    },
  );
});

test("generateExchangePair maps unsupported RSA-OAEP", async () => {
  await withCrypto(
    buildCrypto({
      subtle: {
        generateKey: async () => {
          throw new Error("no");
        },
      },
    }),
    async () => {
      await expectCodeAsync(generateExchangePair, "RSA_OAEP_UNSUPPORTED");
    },
  );
});

test("WrapAgent maps RSA importKey failure", async () => {
  await withCrypto(
    buildCrypto({
      subtle: {
        importKey: async () => {
          throw new Error("no");
        },
      },
    }),
    async () => {
      const agent = new WrapAgent(wrapJwk);
      await expectCodeAsync(() => agent.wrap(cipherJwk), "RSA_OAEP_UNSUPPORTED");
    },
  );
});

test("WrapAgent.wrap maps AES-GCM importKey failure", async () => {
  await withCrypto(
    buildCrypto({
      subtle: {
        importKey: async (_format, _data, algorithm) => {
          if (algorithm?.name === "AES-GCM") throw new Error("no");
          return {};
        },
      },
    }),
    async () => {
      const agent = new WrapAgent(wrapJwk);
      await expectCodeAsync(() => agent.wrap(cipherJwk), "AES_GCM_UNSUPPORTED");
    },
  );
});

test("WrapAgent.wrap maps RSA wrapKey failure", async () => {
  await withCrypto(
    buildCrypto({
      subtle: {
        importKey: async () => ({}),
        wrapKey: async () => {
          throw new Error("no");
        },
      },
    }),
    async () => {
      const agent = new WrapAgent(wrapJwk);
      await expectCodeAsync(() => agent.wrap(cipherJwk), "RSA_OAEP_UNSUPPORTED");
    },
  );
});

test("UnwrapAgent maps RSA importKey failure", async () => {
  await withCrypto(
    buildCrypto({
      subtle: {
        importKey: async () => {
          throw new Error("no");
        },
      },
    }),
    async () => {
      const agent = new UnwrapAgent(unwrapJwk);
      await expectCodeAsync(() => agent.unwrap(new ArrayBuffer(1)), "RSA_OAEP_UNSUPPORTED");
    },
  );
});

test("UnwrapAgent.unwrap maps RSA unwrapKey failure", async () => {
  await withCrypto(
    buildCrypto({
      subtle: {
        importKey: async () => ({}),
        unwrapKey: async () => {
          throw new Error("no");
        },
      },
    }),
    async () => {
      const agent = new UnwrapAgent(unwrapJwk);
      await expectCodeAsync(() => agent.unwrap(new ArrayBuffer(1)), "RSA_OAEP_UNSUPPORTED");
    },
  );
});

test("deriveOID maps unsupported SHA-256", async () => {
  await withCrypto(
    buildCrypto({
      subtle: {
        digest: async () => {
          throw new Error("no");
        },
      },
    }),
    async () => {
      await expectCodeAsync(() => deriveOID(new Uint8Array(32)), "SHA256_UNSUPPORTED");
    },
  );
});


test("generateVerificationPair succeeds with mocked crypto", async () => {
  const publicKey = {};
  const privateKey = {};
  await withCrypto(
    buildCrypto({
      subtle: {
        generateKey: async () => ({ publicKey, privateKey }),
        exportKey: async (_format, key) => (key === privateKey ? signJwk : verifyJwk),
      },
    }),
    async () => {
      const { signJwk, verifyJwk } = await generateVerificationPair();
      assert.deepEqual(signJwk, signJwk);
      assert.deepEqual(verifyJwk, verifyJwk);
    },
  );
});

test("SignAgent/VerifyAgent succeed with mocked crypto", async () => {
  await withCrypto(
    buildCrypto({
      subtle: {
        importKey: async () => ({}),
        sign: async () => new ArrayBuffer(2),
        verify: async () => true,
      },
    }),
    async () => {
      const signer = new SignAgent(signJwk);
      const verifier = new VerifyAgent(verifyJwk);
      const sig = await signer.sign(new Uint8Array([1]));
      assert.ok(sig instanceof ArrayBuffer);
      const ok = await verifier.verify(new Uint8Array([1]), sig);
      assert.equal(ok, true);
    },
  );
});

test("generateExchangePair succeeds with mocked crypto", async () => {
  const publicKey = {};
  const privateKey = {};
  await withCrypto(
    buildCrypto({
      subtle: {
        generateKey: async () => ({ publicKey, privateKey }),
        exportKey: async (_format, key) => (key === publicKey ? wrapJwk : unwrapJwk),
      },
    }),
    async () => {
      const { wrapJwk: w, unwrapJwk: u } = await generateExchangePair();
      assert.deepEqual(w, wrapJwk);
      assert.deepEqual(u, unwrapJwk);
    },
  );
});

test("WrapAgent.wrap succeeds with mocked crypto", async () => {
  await withCrypto(
    buildCrypto({
      subtle: {
        importKey: async () => ({}),
        wrapKey: async () => new ArrayBuffer(4),
      },
    }),
    async () => {
      const agent = new WrapAgent(wrapJwk);
      const wrapped = await agent.wrap(cipherJwk);
      assert.ok(wrapped instanceof ArrayBuffer);
    },
  );
});

test("UnwrapAgent.unwrap succeeds with mocked crypto", async () => {
  await withCrypto(
    buildCrypto({
      subtle: {
        importKey: async () => ({}),
        unwrapKey: async () => ({}),
        exportKey: async () => cipherJwk,
      },
    }),
    async () => {
      const agent = new UnwrapAgent(unwrapJwk);
      const unwrapped = await agent.unwrap(new ArrayBuffer(2));
      assert.equal(unwrapped.k, cipherJwk.k);
    },
  );
});
