import { argon2id } from 'hash-wasm';

self.onmessage = async (e) => {
  try {
    const { password, salt } = e.data;
    const keyArray = await argon2id({
      password: password,
      salt: salt,
      parallelism: 1,
      iterations: 3,
      memorySize: 65536,
      hashLength: 32,
      outputType: 'binary'
    });
    self.postMessage({ success: true, keyArray });
  } catch (error) {
    self.postMessage({ success: false, error: error.message });
  }
};
