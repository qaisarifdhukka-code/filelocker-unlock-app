export class BlobReader {
  constructor(blob) {
    this.blob = blob;
    this.offset = 0;
    this.size = blob.size;
  }

  async readBytes(length) {
    if (this.offset >= this.size) return null;
    const end = Math.min(this.offset + length, this.size);
    const chunk = this.blob.slice(this.offset, end);
    const buf = await chunk.arrayBuffer();
    this.offset = end;
    return new Uint8Array(buf);
  }

  async cancel() {
    // No-op for BlobReader
  }

  async seekToBoundary(boundaryString) {
    // Read the first 2MB, which easily contains the entire HTML template
    const scanSize = Math.min(2 * 1024 * 1024, this.size);
    const chunk = this.blob.slice(0, scanSize);
    const buf = new Uint8Array(await chunk.arrayBuffer());
    
    const searchBytes = new TextEncoder().encode(boundaryString);
    let foundIndex = -1;
    
    for (let i = 0; i <= buf.length - searchBytes.length; i++) {
      let match = true;
      for (let j = 0; j < searchBytes.length; j++) {
        if (buf[i + j] !== searchBytes[j]) {
          match = false;
          break;
        }
      }
      if (match) {
        foundIndex = i;
        break;
      }
    }
    
    if (foundIndex !== -1) {
      this.offset = foundIndex + searchBytes.length;
      return true;
    }
    return false;
  }
}

export class StreamReader {
  constructor(readableStream) {
    this.reader = readableStream.getReader();
    this.buffer = new Uint8Array(0);
    this.done = false;
  }

  async readBytes(length) {
    // Fill buffer until we have enough or stream is done
    while (this.buffer.length < length && !this.done) {
      const { value, done } = await this.reader.read();
      if (done) {
        this.done = true;
        break;
      }
      if (value) {
        const newBuffer = new Uint8Array(this.buffer.length + value.length);
        newBuffer.set(this.buffer, 0);
        newBuffer.set(value, this.buffer.length);
        this.buffer = newBuffer;
      }
    }

    if (this.buffer.length === 0) return null;

    // Return exactly length bytes, or whatever is left
    const toReturn = this.buffer.slice(0, length);
    this.buffer = this.buffer.slice(length);
    return toReturn;
  }

  async cancel() {
    try {
      await this.reader.cancel();
    } catch (e) {
      // Ignore
    }
  }
}
