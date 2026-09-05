// cryptoWorker.js
// PERF FIX 2A: Argon2id key derivation runs in this Web Worker so the main React
// thread (and its animations) stay fully responsive during the ~1-3 second operation.
//
// Protocol:
//   Input message:  { type: 'deriveKey', password: string, saltHex: string }
//   Output message: { type: 'keyDerived', keyArray: ArrayBuffer }
//               OR: { type: 'error', message: string }

import { argon2id } from 'hash-wasm';

function hexToBytes(hex) {
  const b = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) b[i / 2] = parseInt(hex.substr(i, 2), 16);
  return b;
}

self.onmessage = async (e) => {
  const { type, password, saltHex } = e.data;

  if (type === 'deriveKey') {
    try {
      const salt = hexToBytes(saltHex);
      const keyArray = await argon2id({
        password,
        salt,
        parallelism: 1,
        iterations: 3,
        memorySize: 65536,
        hashLength: 32,
        outputType: 'binary',
      });

      // Transfer the ArrayBuffer to the main thread (zero-copy)
      self.postMessage({ type: 'keyDerived', keyArray: keyArray.buffer }, [keyArray.buffer]);
    } catch (err) {
      self.postMessage({ type: 'error', message: err.message });
    }
  }
};