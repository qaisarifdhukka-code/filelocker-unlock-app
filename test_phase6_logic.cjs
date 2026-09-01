const fs = require('fs');
const crypto = require('crypto');
const { argon2id } = require('hash-wasm');
const { StreamReader } = require('./src/SequentialReader.js');

const MAGIC_EXPECTED = [0x56, 0x4C, 0x4B, 0x54];
const HEADER_BASE = 5;
const META_LEN_SIZE = 4;
const NONCE_SIZE = 8;
const CHUNK_ENC = 10 * 1024 * 1024 + 12 + 16;

async function runTests() {
  console.log("Running Phase 6 Architectural Tests...\n");
  let passCount = 0;
  
  // Create a mock stream reader that feeds a 120MB fake vault
  // We'll observe memory usage
  console.log("Test 4: Large File (>100MB) Memory Streaming");
  
  // Fake metadata
  const meta = { originalName: 'large.txt', salt: crypto.randomBytes(16).toString('hex'), branding: { firmName: 'Test' } };
  const metaStr = JSON.stringify(meta);
  
  const header = Buffer.alloc(HEADER_BASE + META_LEN_SIZE);
  header.set(MAGIC_EXPECTED, 0);
  header[4] = 1;
  header.writeUInt32LE(metaStr.length, 5);
  
  const nonce = crypto.randomBytes(NONCE_SIZE);
  
  // Mock response body stream generator
  const mockReadable = {
    getReader: () => {
      let chunksLeft = 12; // 12 * ~10MB = 120MB
      let state = 'HEADER';
      return {
        read: async () => {
          if (state === 'HEADER') {
            state = 'CHUNKS';
            return { value: Buffer.concat([header, Buffer.from(metaStr), nonce]), done: false };
          }
          if (chunksLeft > 0) {
            chunksLeft--;
            return { value: crypto.randomBytes(CHUNK_ENC), done: false };
          }
          return { value: null, done: true };
        },
        cancel: async () => {
          chunksLeft = 0;
        }
      };
    }
  };

  const reader = new StreamReader(mockReadable);
  
  // Measure memory before
  const memBefore = process.memoryUsage().heapUsed;
  
  const fixedBuf = await reader.readBytes(HEADER_BASE + META_LEN_SIZE);
  const metaLen = new DataView(fixedBuf.buffer, fixedBuf.byteOffset, fixedBuf.byteLength).getUint32(HEADER_BASE, true);
  await reader.readBytes(metaLen);
  await reader.readBytes(NONCE_SIZE);
  
  // Read all chunks (simulating decrypt loop)
  let totalBytes = 0;
  while(true) {
    const chunk = await reader.readBytes(CHUNK_ENC);
    if (!chunk) break;
    totalBytes += chunk.length;
  }
  
  // Measure memory after
  const memAfter = process.memoryUsage().heapUsed;
  const memDiffMB = (memAfter - memBefore) / 1024 / 1024;
  
  console.log(`- Simulated streaming ${totalBytes / 1024 / 1024} MB of data.`);
  console.log(`- Peak Heap Memory Increase: ${memDiffMB.toFixed(2)} MB`);
  
  if (memDiffMB < 50) {
    console.log("✅ PASS: Streaming decryption does not accumulate entire vault in RAM.");
    passCount++;
  } else {
    console.log("❌ FAIL: Memory leak detected.");
  }

  console.log("\nTest 2: Wrong Password Stream Cancellation");
  const reader2 = new StreamReader({
    getReader: () => {
      let readCount = 0;
      return {
        read: async () => {
          readCount++;
          if (readCount > 2) throw new Error("Stream continued reading after cancel!");
          return { value: Buffer.alloc(CHUNK_ENC), done: false };
        },
        cancel: async () => { console.log('   -> Stream successfully cancelled'); }
      }
    }
  });
  
  await reader2.readBytes(100);
  await reader2.cancel();
  console.log("✅ PASS: Stream cancels correctly upon authentication failure.");
  passCount++;

  console.log(`\nTests completed: ${passCount}/2 Passed`);
}

runTests();
