import React, { useState, useEffect, useCallback, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
// NOTE: argon2id is no longer imported here — it runs inside cryptoWorker.js
// off the main thread so animations stay smooth during key derivation.
import { ShieldAlert, AlertCircle, Loader2, Eye, EyeOff, Download, FileText, CheckCircle2, Circle, XCircle } from 'lucide-react';
import SecurePDFViewer from './components/SecurePDFViewer';
import SecureImageViewer from './components/SecureImageViewer';
import { SecureMediaViewer } from './components/SecureMediaViewer';
import { APP_CONFIG } from './config';
import logoUrl from './assets/filelocker-logo-main.svg';
import logoDarkUrl from './assets/filelocker-logo-main-dark.svg';
import heroBg from './assets/hero.png';

// ─── Vault Format v1 ──────────────────────────────────────────────────────────
// [MAGIC:4][VERSION:1][META_LEN:4 LE][META_JSON][CHUNK_NONCE:8][CHUNKS...]
// Each chunk: [IV:12][TAG:16][CIPHERTEXT]
const MAGIC_EXPECTED = [0x56, 0x4C, 0x4B, 0x54]; // "VLKT"
const HEADER_BASE    = 5;   // MAGIC(4) + VERSION(1)
const META_LEN_SIZE  = 4;
const NONCE_SIZE     = 8;
const CHUNK_PLAIN    = 10 * 1024 * 1024; // 10 MB
const CHUNK_ENC      = CHUNK_PLAIN + 12 + 16; // + IV + TAG

function hexToBytes(hex) {
  const b = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) b[i / 2] = parseInt(hex.substr(i, 2), 16);
  return b;
}

// ─── MIME type map for Secure Viewer ──────────────────────────────────────────
function getMimeType(ext) {
  const map = {
    '.pdf':  'application/pdf',
    '.png':  'image/png',
    '.jpg':  'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.gif':  'image/gif',
    '.webp': 'image/webp',
    '.svg':  'image/svg+xml',
    '.mp4':  'video/mp4',
    '.webm': 'video/webm',
    '.mov':  'video/quicktime',
    '.mkv':  'video/x-matroska',
    '.mp3':  'audio/mpeg',
    '.wav':  'audio/wav',
    '.ogg':  'audio/ogg',
    '.m4a':  'audio/mp4',
    '.txt':  'text/plain',
    '.md':   'text/plain',
    '.csv':  'text/csv',
    '.json': 'application/json',
    '.xml':  'application/xml',
    '.log':  'text/plain',
  };
  return map[ext] || 'application/octet-stream';
}

function getViewerType(ext) {
  if (['.pdf'].includes(ext)) return 'pdf';
  if (['.png','.jpg','.jpeg','.gif','.webp','.svg'].includes(ext)) return 'image';
  if (['.mp4','.webm','.mov','.mkv'].includes(ext)) return 'video';
  if (['.mp3','.wav','.ogg','.m4a'].includes(ext)) return 'audio';
  if (['.txt','.md','.csv','.json','.xml','.log'].includes(ext)) return 'text';
  return 'download_only';
}

export default function App() {
  const [file,     setFile]     = useState(null);
  const [meta, setMeta] = useState(null);
  const [branding, setBranding] = useState(null);
  const [isBlurred, setIsBlurred] = useState(false);

  // Anti-Screenshot (Blur on Blur)
  useEffect(() => {
    const handleBlur = () => setIsBlurred(true);
    const handleFocus = () => setIsBlurred(false);

    window.addEventListener('blur', handleBlur);
    window.addEventListener('focus', handleFocus);
    
    return () => {
      window.removeEventListener('blur', handleBlur);
      window.removeEventListener('focus', handleFocus);
    };
  }, []);
  const [password, setPassword] = useState('');
  const [status, setStatus] = useState('IDLE'); // IDLE, DECRYPTING, ERROR, DONE, VIEWING
  const [isDeriving, setIsDeriving] = useState(false);
  const [decryptStage, setDecryptStage] = useState(0); // 0: Key, 1: Chunks, 2: Finalizing
  const [errorMsg, setErrorMsg] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [isEmbedded,   setIsEmbedded]   = useState(false);
  const [progress, setProgress] = useState(0);
  const [viewerBlobUrl, setViewerBlobUrl] = useState(null);
  const [textContent, setTextContent] = useState('');
  const [isCloudLoading, setIsCloudLoading] = useState(false);
  const [downloadProgress, setDownloadProgress] = useState(0);
  const [isRetrying, setIsRetrying] = useState(false); // UX FIX 6: shows retry banner mid-decrypt

  // UX FIX 1: Detect synchronously (no async) whether this page is a cloud link.
  // This allows us to immediately show the password input rather than blocking behind
  // a loading spinner while the 1MB header fetch completes in the background.
  const isCloudLink = (() => {
    if (window.location.protocol === 'file:') return false;
    const parts = window.location.pathname.split('/').filter(Boolean);
    return parts.length >= 2;
  })();

  // UX FIX 1: Holds the in-flight loadCloudVault() promise so decryptVault()
  // can await it if the user clicks Unlock before the header fetch completes.
  const loadCloudVaultPromiseRef = useRef(null);

  // PERF FIX 2A: Persistent Web Worker for Argon2id key derivation.
  // Created once on mount, reused for every unlock attempt.
  // This keeps the main thread free so animations stay smooth.
  const cryptoWorkerRef = useRef(null);
  useEffect(() => {
    cryptoWorkerRef.current = new Worker(
      new URL('./cryptoWorker.js', import.meta.url),
      { type: 'module' }
    );
    return () => {
      cryptoWorkerRef.current?.terminate();
    };
  }, []);

  // Helper: derive a CryptoKey via the Web Worker (off main thread).
  const deriveKeyInWorker = (password, saltHex) =>
    new Promise((resolve, reject) => {
      const worker = cryptoWorkerRef.current;
      if (!worker) return reject(new Error('Crypto worker not available.'));
      
      const timeoutId = setTimeout(() => {
        worker.removeEventListener('message', onMessage);
        worker.removeEventListener('error', onError);
        reject(new Error('Key derivation timed out.'));
      }, 15000);

      const onMessage = async (e) => {
        clearTimeout(timeoutId);
        worker.removeEventListener('message', onMessage);
        worker.removeEventListener('error', onError);
        if (e.data.type === 'keyDerived') {
          try {
            const key = await crypto.subtle.importKey(
              'raw', e.data.keyArray, { name: 'AES-GCM' }, false, ['decrypt']
            );
            resolve(key);
          } catch (err) { reject(err); }
        } else {
          reject(new Error(e.data.message || 'Key derivation failed.'));
        }
      };

      const onError = (e) => {
        clearTimeout(timeoutId);
        worker.removeEventListener('message', onMessage);
        worker.removeEventListener('error', onError);
        reject(new Error('Crypto worker crashed or failed to load.'));
      };

      worker.addEventListener('message', onMessage);
      worker.addEventListener('error', onError);
      // Use the saltHex argument directly (not from closure) to avoid stale-state bugs
      worker.postMessage({ type: 'deriveKey', password, saltHex });
    });


  // QUALITY FIX 3A: Fetch with retry + Range-header support for cloud vault streaming.
  // If the connection drops mid-download, we retry from the last received byte offset.
  const fetchWithRetry = useCallback(async (url, options = {}, maxRetries = 4) => {
    let lastErr;
    for (let attempt = 0; attempt < maxRetries; attempt++) {
      try {
        const res = await fetch(url, options);
        if (!res.ok && res.status >= 500) {
          const text = await res.text().catch(() => '');
          throw new Error(`Server error ${res.status}: ${text}`);
        }
        return res;
      } catch (err) {
        lastErr = err;
        if (attempt < maxRetries - 1) {
          await new Promise(r => setTimeout(r, 1000 * Math.pow(2, attempt)));
        }
      }
    }
    throw lastErr;
  }, []);

  // References to OPFS files for cleanup
  const activeOpfsHandles = useRef([]);
  
  const trackOpfsHandle = (handle) => {
    activeOpfsHandles.current.push(handle);
  };

  const cleanupOpfs = async () => {
    try {
      const root = await navigator.storage.getDirectory();
      for (const handle of activeOpfsHandles.current) {
        try {
          await root.removeEntry(handle.name);
        } catch(e) {}
      }
      activeOpfsHandles.current = [];
    } catch(e) {}
  };

  // ── Auto-load embedded vault (Single-File Mode) ────────────────────────────
  // The provisioning app injects a <script id="vault-payload" type="text/plain">
  // tag containing the base64-encoded .vault bytes directly into this HTML file.
  // If that tag exists, we skip the "Select Vault File" step entirely.
  const loadEmbeddedVault = useCallback(() => {
    const embeddedScript = document.getElementById('vault-payload');
    if (!embeddedScript) return false;

    try {
      const base64 = embeddedScript.textContent.trim();
      const binaryStr = atob(base64);
      const bytes = new Uint8Array(binaryStr.length);
      for (let i = 0; i < binaryStr.length; i++) {
        bytes[i] = binaryStr.charCodeAt(i);
      }

      // Parse the vault header (same logic as selectVault)
      const fixedBuf = bytes.buffer.slice(0, HEADER_BASE + META_LEN_SIZE);
      const fixedArr = new Uint8Array(fixedBuf);
      for (let i = 0; i < 4; i++) {
        if (fixedArr[i] !== MAGIC_EXPECTED[i]) throw new Error('Invalid vault signature.');
      }
      const metaLen   = new DataView(fixedBuf).getUint32(HEADER_BASE, true);
      const metaStart = HEADER_BASE + META_LEN_SIZE;
      const metaBytes = bytes.slice(metaStart, metaStart + metaLen);
      const parsedMeta = JSON.parse(new TextDecoder().decode(metaBytes));
      const dataStart  = metaStart + metaLen + NONCE_SIZE;

      // Wrap bytes in a File so decryptVault() works unchanged
      const vaultFile = new File(
        [new Blob([bytes])],
        parsedMeta.originalName + '.vault',
        { type: 'application/octet-stream' }
      );

      setFile(vaultFile);
      setMeta({ ...parsedMeta, dataStart });
      setBranding(parsedMeta.branding || null);
      setIsEmbedded(true);
      return true;
    } catch (err) {
      setErrorMsg('Could not load embedded vault: ' + err.message);
      return false;
    }
  }, []);

  const loadCloudVault = useCallback(async () => { console.log('loadCloudVault called, pathname:', window.location.pathname, 'API_URL:', APP_CONFIG.API_URL);
    if (window.location.protocol === 'file:') return false;
    
    // URL pattern: /:firmSlug/:linkId
    const pathParts = window.location.pathname.split('/').filter(Boolean);
    if (pathParts.length < 2) return false;

    const linkId = pathParts[pathParts.length - 1];
    
    try {
      setIsCloudLoading(true);
      setErrorMsg('');
      
      const API_BASE = APP_CONFIG.API_URL;
      
      // Fetch metadata first to get the total file size
      const metaRes = await fetch(`${API_BASE}/api/links/${linkId}`);
      if (!metaRes.ok) throw new Error('Failed to fetch link metadata.');
      const linkMeta = await metaRes.json();
      
      // Fetch just the first 1MB to get the header
      const dlRes = await fetch(`${API_BASE}/api/links/${linkId}/download`, {
        method: 'POST',
        headers: { 'Range': 'bytes=0-1048575' }
      });

      if (!dlRes.ok && dlRes.status !== 206) {
        let msg = 'Failed to download secure vault header.';
        try { const errData = await dlRes.json(); if (errData.error) msg = errData.error; } catch(e) {}
        throw new Error(msg);
      }
      
      const fixedBuf = await dlRes.arrayBuffer();
      const fixedArr = new Uint8Array(fixedBuf);
      
      // Parse the fixed header
      if (fixedArr.length < HEADER_BASE + META_LEN_SIZE) throw new Error('File too small.');
      for (let i = 0; i < 4; i++) {
        if (fixedArr[i] !== MAGIC_EXPECTED[i]) throw new Error('Not a valid FileLocker file.');
      }
      const metaLen = new DataView(fixedBuf).getUint32(HEADER_BASE, true);
      
      // Parse metadata
      const metaStart = HEADER_BASE + META_LEN_SIZE;
      const metaBuf   = fixedBuf.slice(metaStart, metaStart + metaLen);
      const parsedMeta = JSON.parse(new TextDecoder().decode(metaBuf));
      const dataStart  = metaStart + metaLen + NONCE_SIZE;

      // Create a virtual file object to represent the cloud vault
      setFile({ size: linkMeta.file_size, isVirtual: true, linkId });
      setMeta({ ...parsedMeta, dataStart });
      setBranding(parsedMeta.branding || null);
      
    } catch (err) {
      console.error('loadCloudVault Error:', err); setErrorMsg(err.message);
      return { success: false, error: err.message };
    } finally {
      setIsCloudLoading(false);
    }
    return { success: true };
  }, []);

  useEffect(() => {
    if (!loadEmbeddedVault()) {
      // UX FIX 1: Store the promise so decryptVault() can await it if needed.
      loadCloudVaultPromiseRef.current = loadCloudVault();
    }
  }, [loadEmbeddedVault, loadCloudVault]);

  // ── Select & parse vault header ────────────────────────────────────────────
  const selectVault = async () => {
    try {
      let selected;
      if (window.showOpenFilePicker) {
        const [fh] = await window.showOpenFilePicker({
          types: [{ description: 'Vault Files', accept: { '*/*': ['.vault'] } }]
        });
        selected = await fh.getFile();
      } else {
        selected = await new Promise((resolve, reject) => {
          const input = document.createElement('input');
          input.type = 'file';
          input.accept = '.vault';
          input.onchange = (e) => {
            if (e.target.files && e.target.files.length > 0) resolve(e.target.files[0]);
            else reject(new Error('AbortError'));
          };
          input.click();
        });
      }

      // Read fixed header: MAGIC(4) + VERSION(1) + META_LEN(4)
      const fixedBuf = await selected.slice(0, HEADER_BASE + META_LEN_SIZE).arrayBuffer();
      const fixedArr = new Uint8Array(fixedBuf);

      // Verify magic
      for (let i = 0; i < 4; i++) {
        if (fixedArr[i] !== MAGIC_EXPECTED[i]) throw new Error('Not a valid FileLocker file.');
      }
      const version = fixedArr[4]; // for future use
      const metaLen = new DataView(fixedBuf).getUint32(HEADER_BASE, true);

      // Read metadata JSON
      const metaStart = HEADER_BASE + META_LEN_SIZE;
      const metaBuf   = await selected.slice(metaStart, metaStart + metaLen).arrayBuffer();
      const parsedMeta = JSON.parse(new TextDecoder().decode(metaBuf));

      // Data starts after: MAGIC+VERSION+META_LEN+META_JSON+CHUNK_NONCE
      const dataStart = metaStart + metaLen + NONCE_SIZE;

      setFile(selected);
      setMeta({ ...parsedMeta, dataStart });
      setBranding(parsedMeta.branding || null);
      setErrorMsg('');
    } catch (err) {
      if (err.name !== 'AbortError') console.error('loadCloudVault Error:', err); setErrorMsg(err.message);
    }
  };

  // ── Decrypt vault ──────────────────────────────────────────────────────────
  const decryptVault = async () => {
    if (!password) { setErrorMsg('Please enter a password.'); return; }
    if (isDeriving) return;

    try {
      setIsDeriving(true);
      setErrorMsg('');

      // UX FIX 1: If the user clicked Unlock while the header fetch was still in-flight,
      // wait for it to complete before attempting key derivation.
      if (loadCloudVaultPromiseRef.current) {
        const cloudLoadResult = await loadCloudVaultPromiseRef.current;
        loadCloudVaultPromiseRef.current = null;
        
        // If the background cloud load failed, we must abort and show its error.
        // This prevents the generic "Failed to load vault metadata" from overwriting
        // a specific error like "Link is expired, consumed, or not found".
        if (cloudLoadResult && cloudLoadResult.success === false) {
           setIsDeriving(false);
           setErrorMsg(cloudLoadResult.error || 'Failed to load vault metadata. Check your connection and try again.');
           return;
        }
      }

      // At this point meta must be set. If it's still null, the cloud load failed
      // before UX FIX 1 was added or in some other edge case.
      if (!meta) {
        setIsDeriving(false);
        setErrorMsg(errorMsg || 'Failed to load vault metadata. Check your connection and try again.');
        return;
      }

      // PERF FIX 2A: Derive key via Web Worker (off main thread).
      // The spinner and stage indicator animate freely during this ~1-3s operation.
      // deriveKeyInWorker posts the password + salt to cryptoWorker.js, receives the
      // raw key bytes back, then imports them as a CryptoKey on the main thread.
      const key = await deriveKeyInWorker(password, meta.salt);

      let downloadName = meta.originalName;
      if (meta.encryptedName) {
        try {
          const encNameBuf = hexToBytes(meta.encryptedName);
          const nameIv = encNameBuf.slice(0, 12);
          const nameTag = encNameBuf.slice(12, 28);
          const nameData = encNameBuf.slice(28);
          const combinedName = new Uint8Array(nameData.byteLength + nameTag.byteLength);
          combinedName.set(new Uint8Array(nameData), 0);
          combinedName.set(new Uint8Array(nameTag), nameData.byteLength);
          const decName = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nameIv }, key, combinedName);
          downloadName = new TextDecoder().decode(decName);
        } catch(e) {
          throw new Error('Invalid password or corrupted vault file.');
        }
      }

      // PRE-FLIGHT CHECK: Attempt to decrypt the first chunk to verify the password
      // BEFORE asking the user where to save the file.
      const dataStart = meta.dataStart;
      const dataSize  = file.size - dataStart;
      
      // QUALITY FIX 3A: Cloud streaming with retry.
      // We track the byte offset of what we have successfully received so far.
      // If the network drops, we re-open the fetch from that offset rather than
      // restarting from the beginning.
      let sourceStreamReader = null;
      let cloudByteOffset = dataStart; // tracks absolute position in cloud file for retries
      let leftover = new Uint8Array(0);
      let offset = dataStart;
      let isStreamDone = false;

      const openCloudStream = async (fromByte, isRetryCall = false) => {
        if (isRetryCall) setIsRetrying(true);
        const API_BASE = APP_CONFIG.API_URL;
        const res = await fetchWithRetry(`${API_BASE}/api/links/${file.linkId}/download`, {
          method: 'POST',
          headers: { 'Range': `bytes=${fromByte}-` }
        });
        setIsRetrying(false); // Clear retry banner once we have a new connection
        if (!res.ok && res.status !== 206) {
          throw new Error(`Download failed with status ${res.status}`);
        }
        return res.body.getReader();
      };

      if (file.isVirtual) {
        sourceStreamReader = await openCloudStream(dataStart);
      }

      const getNextChunk = async () => {
         while (!isStreamDone && leftover.length < CHUNK_ENC) {
            if (file.isVirtual) {
               try {
                 const { done, value } = await sourceStreamReader.read();
                 if (value) {
                   // Track how many bytes we have received for potential retry resumption
                   cloudByteOffset += value.length;
                   const newLeftover = new Uint8Array(leftover.length + value.length);
                   newLeftover.set(leftover, 0);
                   newLeftover.set(value, leftover.length);
                   leftover = newLeftover;
                 }
                 if (done) isStreamDone = true;
               } catch (networkErr) {
                 // QUALITY FIX 3A + UX FIX 6: Network error mid-stream — re-open from last known offset.
                 // isRetryCall=true triggers the retry banner in the UI.
                 console.warn('Cloud stream interrupted, retrying from offset', cloudByteOffset, networkErr);
                 sourceStreamReader = await openCloudStream(cloudByteOffset, true);
               }
            } else {
               const chunkEnd = Math.min(file.size, offset + Math.max(CHUNK_ENC * 2, 20 * 1024 * 1024));
               if (offset >= file.size) { isStreamDone = true; }
               else {
                 const chunkBuf = new Uint8Array(await file.slice(offset, chunkEnd).arrayBuffer());
                 const newLeftover = new Uint8Array(leftover.length + chunkBuf.length);
                 newLeftover.set(leftover, 0);
                 newLeftover.set(chunkBuf, leftover.length);
                 leftover = newLeftover;
                 offset = chunkEnd;
               }
            }
         }
         if (leftover.length === 0) return null;
         let chunkLen = Math.min(CHUNK_ENC, leftover.length);
         if (isStreamDone && leftover.length < CHUNK_ENC) chunkLen = leftover.length;
         
         const chunkBuf = leftover.slice(0, chunkLen);
         leftover = leftover.slice(chunkLen);
         return chunkBuf;
      };

      const firstChunkBuf = await getNextChunk();
      if (firstChunkBuf && firstChunkBuf.byteLength >= 28) {
        const iv       = firstChunkBuf.slice(0, 12);
        const tag      = firstChunkBuf.slice(12, 28);
        const data     = firstChunkBuf.slice(28);
        const combined = new Uint8Array(data.byteLength + tag.byteLength);
        combined.set(new Uint8Array(data), 0);
        combined.set(new Uint8Array(tag), data.byteLength);
        // If password is wrong, this will throw an OperationError instantly
        await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, combined);
      }
      
      setPassword('');

      // If we reach here, the password is correct!
      setIsDeriving(false);
      setStatus('DECRYPTING');
      setProgress(0);
      setDecryptStage(1);

      // In secure_view mode, ALWAYS collect into memory (never stream to disk)
      const isSecureView = meta.viewerConfig?.mode === 'secure_view';
      let writable;
      let chunks = [];
      const isFallback = !window.showSaveFilePicker || isSecureView;
      
      const LARGE_FILE_THRESHOLD = 150 * 1024 * 1024;
      const useOPFSFallback = isFallback && (file.size >= LARGE_FILE_THRESHOLD) && navigator.storage;
      let opfsDecryptedHandle = null;

      if (!isFallback) {
        try {
          const saveFh = await window.showSaveFilePicker({ suggestedName: downloadName });
          writable = await saveFh.createWritable();
        } catch (err) {
          throw new Error(`Failed to save file: ${err.message}. If you are trying to save to a protected folder, please select a different location.`);
        }
      } else if (useOPFSFallback) {
        try {
          const root = await navigator.storage.getDirectory();
          opfsDecryptedHandle = await root.getFileHandle(`decrypted_${Date.now()}_${downloadName}`, { create: true });
          trackOpfsHandle(opfsDecryptedHandle);
          writable = await opfsDecryptedHandle.createWritable();
        } catch (err) {
          throw new Error(`Secure View for large files requires browser local storage (OPFS), which is restricted when opening HTML files locally in this browser. Please use the secure cloud link instead, or ask the sender to allow downloading. (Technical error: ${err.message})`);
        }
      }
      
      let totalProcessed = 0;
      const processChunk = async (chunkBuf) => {
        if (chunkBuf.byteLength < 28) return;
        const iv       = chunkBuf.slice(0, 12);
        const tag      = chunkBuf.slice(12, 28);
        const data     = chunkBuf.slice(28);
        const combined = new Uint8Array(data.byteLength + tag.byteLength);
        combined.set(new Uint8Array(data), 0);
        combined.set(new Uint8Array(tag), data.byteLength);
        
        const dec = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, combined);
        if (!isFallback) await writable.write(dec);
        else if (useOPFSFallback) await writable.write(dec);
        else chunks.push(new Uint8Array(dec));
        
        totalProcessed += chunkBuf.byteLength;
        setProgress(Math.min(100, Math.round((totalProcessed / dataSize) * 100)));
      };

      if (firstChunkBuf) await processChunk(firstChunkBuf);

      while (true) {
        const chunkBuf = await getNextChunk();
        if (!chunkBuf) break;
        await processChunk(chunkBuf);
      }

      setDecryptStage(2);

      if (isSecureView) {
        // Secure View mode: render in-browser viewer
        const mimeType = getMimeType(meta.ext);
        let blob;
        if (useOPFSFallback) {
          await writable.close();
          blob = await opfsDecryptedHandle.getFile();
        } else {
          blob = new Blob(chunks, { type: mimeType });
        }
        
        const url = URL.createObjectURL(blob);
        const viewType = getViewerType(meta.ext);
        if (viewType === 'text') {
          // Pre-load text content for display
          const text = await blob.text();
          setTextContent(text);
        }
        setViewerBlobUrl(url);
        setStatus('VIEWING');
      } else if (isFallback) {
        let blob;
        if (useOPFSFallback) {
          await writable.close();
          blob = await opfsDecryptedHandle.getFile();
        } else {
          blob = new Blob(chunks);
        }
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = downloadName;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        setStatus('DONE');
      } else {
        await writable.close();
        setStatus('DONE');
      }
    } catch (err) {
      console.error(err);
      setIsDeriving(false);
      setStatus('IDLE');
      const msg = err.message || '';
      setErrorMsg(
        err.name === 'OperationError' || msg.includes('auth') || msg.includes('operation') || msg.includes('Invalid password')
          ? 'Invalid password. Please try again.'
          : (msg || 'Decryption failed.')
      );
    }
  };

  const reset = () => {
    setPassword('');
    setStatus('IDLE');
    setProgress(0);
    setDownloadProgress(0);
    setDecryptStage(0);
    setErrorMsg('');
    if (viewerBlobUrl) { URL.revokeObjectURL(viewerBlobUrl); setViewerBlobUrl(null); }
    setTextContent('');
    cleanupOpfs();
    // In embedded mode the vault is baked into the HTML — keep file & meta.
    if (!isEmbedded) {
      setFile(null);
      setMeta(null);
      setBranding(null);
    }
  };

  // ── UI ─────────────────────────────────────────────────────────────────────
  
  const fadeVariants = {
    initial: { opacity: 0, y: 10, scale: 0.98 },
    animate: { opacity: 1, y: 0, scale: 1 },
    exit: { opacity: 0, y: -10, scale: 0.98 },
  };

  return (
    <div className={`min-h-screen flex flex-col md:flex-row w-full bg-white transition-all duration-300 ${isBlurred ? 'blur-xl select-none pointer-events-none' : ''}`}>
      {branding && branding.primaryColor && (
        <style dangerouslySetInnerHTML={{__html: `
          :root { --brand-primary: ${branding.primaryColor}; }
          .bg-\\[\\#2563EB\\] { background-color: var(--brand-primary) !important; border-color: var(--brand-primary) !important; }
          .text-\\[\\#2563EB\\] { color: var(--brand-primary) !important; }
          .text-\\[\\#0073bb\\] { color: var(--brand-primary) !important; }
          .border-\\[\\#1e40af\\] { border-color: var(--brand-primary) !important; }
          .hover\\:bg-\\[\\#1d4ed8\\]:hover { filter: brightness(0.9); background-color: var(--brand-primary) !important; }
        `}} />
      )}
        
      {/* Left Side: Brand Panel */}
      <div className="hidden md:flex flex-col justify-between w-5/12 p-12 lg:p-16 relative overflow-hidden bg-[#0F1629]">
        
        {/* Global Hero Image Background */}
        <div className="absolute inset-0 z-0">
          <img src={heroBg} alt="" className="w-full h-full object-cover opacity-80" />
        </div>
        
        <div className="absolute inset-0 bg-gradient-to-t from-[#0F1629] via-transparent to-transparent z-0 opacity-80"></div>
        
        <div className="relative z-10">
          {branding?.logoBase64 ? (
            <img src={branding.logoBase64} alt={branding.firmName || "Firm Logo"} className="h-[48px] w-auto max-w-[200px] object-contain" />
          ) : (
            <img src={logoDarkUrl} alt="FileLocker Logo" className="h-[36px] w-auto" />
          )}
        </div>

        <div className="relative z-10 mt-16 max-w-md">
          <p className="text-[13px] font-bold text-[#2563EB] tracking-wider uppercase mb-4">Enterprise Grade Security</p>
          <h2 className="text-[32px] lg:text-[40px] font-bold text-white leading-tight mb-6">Secure offline file delivery for professionals.</h2>
          <p className="text-[#94A3B8] text-[16px] lg:text-[18px] leading-relaxed">
            Your sensitive files, encrypted to military-grade standards and protected completely offline.
          </p>
        </div>
      </div>

      {/* Right Side: Interactive Panel */}
      <div className="w-full md:w-7/12 p-8 md:p-12 lg:p-20 flex flex-col justify-center items-center relative bg-white">
        
        <div className="w-full max-w-sm text-left mx-auto">
          <div className="flex md:hidden mb-10">
            {branding?.logoBase64 ? (
              <img src={branding.logoBase64} alt={branding.firmName || "Firm Logo"} className="h-[40px] w-auto max-w-[200px] object-contain" />
            ) : (
              <img src={logoUrl} alt="FileLocker Logo" className="h-[36px] w-auto" />
            )}
          </div>

          <AnimatePresence mode="wait">
          {/* STATE: IDLE — no file selected (only for local vault selection) */}
          {status === 'IDLE' && !file && !(isCloudLink && !isEmbedded) && (
            <motion.div key="state-no-file" variants={fadeVariants} initial="initial" animate="animate" exit="exit" transition={{ duration: 0.2 }}>
              <h2 className="text-[20px] font-bold mb-5 pb-3 border-b border-gray-200 text-[#16191f] flex items-center">
                {branding?.firmName ? branding.firmName : "Vault Unlock"} <ShieldAlert className="w-[18px] h-[18px] ml-2 text-[#0073bb] stroke-[2px]" />
              </h2>
              
              <div className="mb-6">
                <label className="block text-[14px] font-medium text-[#16191f] mb-1">
                  Secure Document Delivery
                </label>
                <div className="text-[13px] text-[#545b64] p-4 bg-[#f8f9fa] border border-[#eaeded] rounded-lg text-center mt-4">
                  Please use the secure link provided by your sender, open your secure HTML package directly, or select a Vault file.
                </div>
              </div>
              <button onClick={selectVault}
                className="w-full py-1.5 px-4 rounded-[2px] bg-[#2563EB] font-bold text-white hover:bg-[#1d4ed8] transition-colors border border-[#1e40af] shadow-[0_1px_1px_rgba(0,0,0,0.1)]">
                Select Vault File
              </button>
              
              {errorMsg && (
                <div className="mt-6 p-3 rounded-[2px] text-[13px] border-l-4 border-[#d13212] bg-[#fdf3f1] text-[#d13212] flex items-start">
                  <AlertCircle className="w-4 h-4 mr-2 mt-0.5 shrink-0" />
                  <span>{errorMsg}</span>
                </div>
              )}
              
              {!window.showSaveFilePicker && (
                <div className="mt-4 p-3 rounded-[2px] text-[13px] text-left bg-[#f8f8f8] border border-[#eaeded] text-[#545b64] flex items-start">
                  <ShieldAlert className="w-4 h-4 mr-2 mt-0.5 shrink-0 text-[#0073bb]" />
                  <span><strong>Browser Note:</strong> You are using Firefox or Safari. Vault sizes are limited to ~1GB to prevent memory crashes. For unlimited sizes, please use Chrome or Edge.</span>
                </div>
              )}
            </motion.div>
          )}

          {/* STATE: IDLE — file selected OR cloud link loading (show password immediately) */}
          {/* UX FIX 1: For cloud links, render the password form immediately without waiting
               for the 1MB header fetch. When meta is null, we show a skeleton for the filename.
               The Unlock button will await the load if still in-flight. */}
          {status === 'IDLE' && (file || (isCloudLink && !isEmbedded)) && (
            <motion.div key="state-password" variants={fadeVariants} initial="initial" animate="animate" exit="exit" transition={{ duration: 0.2 }}>
              
              <h2 className="text-[20px] font-bold mb-5 pb-3 border-b border-gray-200 text-[#16191f] flex items-center">
                {branding?.firmName ? branding.firmName : "Vault Unlock"} <ShieldAlert className="w-[18px] h-[18px] ml-2 text-[#0073bb] stroke-[2px]" />
              </h2>

              <div className="mb-4">
                <label className="block text-[14px] font-medium text-[#16191f] mb-1">
                  Secure delivery{!isEmbedded && file && (
                    <span className="text-[#0073bb] font-normal hover:underline cursor-pointer ml-1" onClick={reset}>(Change?)</span>
                  )}
                </label>
                {/* UX FIX 1: Skeleton shimmer when the vault header is still being fetched */}
                {meta ? (
                  <div className="w-full px-3 py-1.5 text-[14px] bg-[#f2f3f3] border border-[#aab7b8] rounded-[2px] text-[#545b64] font-mono truncate">
                    {meta.originalName}
                  </div>
                ) : (
                  <div className="w-full px-3 py-2 bg-[#f2f3f3] border border-[#aab7b8] rounded-[2px] flex items-center gap-2">
                    <div className="h-3 w-3/4 bg-gray-300 rounded animate-pulse" />
                    <span className="text-[12px] text-[#0073bb] ml-auto">Loading...</span>
                  </div>
                )}
              </div>

              <div className="mb-4">
                <label className="block text-[14px] font-medium text-[#16191f] mb-1">Password</label>
                <input
                  type={showPassword ? "text" : "password"}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && decryptVault()}
                  autoFocus
                  className={`w-full px-3 py-1.5 text-[14px] bg-white border ${errorMsg ? 'border-[#d13212] focus:border-[#d13212] focus:shadow-[0_0_0_1px_#d13212]' : 'border-[#aab7b8] focus:border-[#0073bb] focus:shadow-[0_0_0_1px_#0073bb]'} rounded-[2px] focus:outline-none transition-shadow`} />
              </div>

              <div className="flex items-center justify-between mb-6">
                <label className="flex items-center text-[13px] text-[#16191f] cursor-pointer">
                  <input type="checkbox" className="mr-2 w-3.5 h-3.5 border-[#545b64] rounded-sm cursor-pointer accent-[#0073bb]" checked={showPassword} onChange={() => setShowPassword(!showPassword)} />
                  Show Password
                </label>
                {meta?.hint && (
                  <span className="text-[13px] text-[#0073bb] hover:underline cursor-help" title={meta.hint}>Having trouble?</span>
                )}
              </div>

              <button onClick={decryptVault} disabled={isDeriving}
                className={`w-full py-1.5 px-4 rounded-[2px] font-bold text-white transition-colors border shadow-[0_1px_1px_rgba(0,0,0,0.1)] flex items-center justify-center ${isDeriving ? 'bg-blue-400 border-blue-400 cursor-wait' : 'bg-[#2563EB] hover:bg-[#1d4ed8] border-[#1e40af]'}`}>
                {isDeriving ? (
                  <><Loader2 className="w-4 h-4 mr-2 animate-spin" /> {!meta ? 'Loading vault...' : 'Verifying...'}</>
                ) : (
                  'Unlock & Download'
                )}
              </button>

              {/* UX FIX 2: Browser memory warning — shown before decryption if Firefox/Safari + large file */}
              {!window.showSaveFilePicker && file?.isVirtual && file?.size > 1024 * 1024 * 1024 && (
                <div className="mt-4 p-3 rounded-[2px] text-[13px] text-left bg-amber-50 border-l-4 border-amber-400 text-amber-800 flex items-start">
                  <ShieldAlert className="w-4 h-4 mr-2 mt-0.5 shrink-0 text-amber-500" />
                  <span>
                    <strong>Browser Limitation:</strong> Your browser doesn't support direct-to-disk saving.
                    Decrypting this large file ({file.size >= 1e9 ? (file.size / 1e9).toFixed(1) + ' GB' : Math.round(file.size / 1e6) + ' MB'}) may
                    crash your browser tab. We strongly recommend opening this link in{' '}
                    <strong>Chrome</strong> or <strong>Edge</strong> for reliable large file decryption.
                  </span>
                </div>
              )}

              {errorMsg && (
                <div className="mt-4 p-3 rounded-[2px] text-[13px] border-l-4 border-[#d13212] bg-[#fdf3f1] text-[#d13212] flex items-start">
                  <AlertCircle className="w-4 h-4 mr-2 mt-0.5 shrink-0" />
                  <span>{errorMsg}</span>
                </div>
              )}
            </motion.div>
          )}


          {/* STATE: DECRYPTING (Pipeline UI) */}
          {status === 'DECRYPTING' && (
            <motion.div key="state-decrypting" variants={fadeVariants} initial="initial" animate="animate" exit="exit" transition={{ duration: 0.2 }} className="text-left py-4">
              <h2 className="text-[20px] font-bold mb-5 pb-3 border-b border-gray-200 text-[#16191f]">
                Decrypting Vault
              </h2>

              {/* UX FIX 6: Network retry banner — shown when stream reconnects mid-decrypt */}
              {isRetrying && (
                <div className="mb-4 px-3 py-2 rounded-[2px] text-[12px] bg-amber-50 border border-amber-300 text-amber-800 flex items-center gap-2">
                  <Loader2 className="w-3.5 h-3.5 animate-spin shrink-0 text-amber-600" />
                  Network unstable — resuming download from where it left off...
                </div>
              )}
              <div className="flex flex-col relative mt-4">
                {/* Vertical connecting line */}
                <div className="absolute left-3 top-4 bottom-8 w-0.5 bg-gray-100 -z-10"></div>
                
                {/* Stage 1: Deriving Key */}
                <div className="flex items-start gap-4 mb-8">
                  <div className="bg-white pt-1">
                    {decryptStage > 0 ? (
                      <CheckCircle2 className="w-6 h-6 text-[#10B981]" />
                    ) : (
                      <Loader2 className="w-6 h-6 text-[#2563EB] animate-spin" />
                    )}
                  </div>
                  <div>
                    <h3 className={`text-[15px] font-bold ${decryptStage > 0 ? 'text-gray-900' : 'text-[#2563EB]'}`}>
                      Secure Key Derivation
                    </h3>
                    <p className="text-[13px] text-gray-500 mt-1">
                      Generating cryptographic key using Argon2id
                    </p>
                  </div>
                </div>

                {/* Stage 2: Decrypting Chunks */}
                <div className="flex items-start gap-4 mb-8">
                  <div className="bg-white pt-1">
                    {decryptStage > 1 ? (
                      <CheckCircle2 className="w-6 h-6 text-[#10B981]" />
                    ) : decryptStage === 1 ? (
                      <Loader2 className="w-6 h-6 text-[#2563EB] animate-spin" />
                    ) : (
                      <Circle className="w-6 h-6 text-gray-300" />
                    )}
                  </div>
                  <div className="flex-1">
                    <h3 className={`text-[15px] font-bold ${decryptStage > 1 ? 'text-gray-900' : decryptStage === 1 ? 'text-[#2563EB]' : 'text-gray-400'}`}>
                      Military-Grade Decryption
                    </h3>
                    <p className={`text-[13px] mt-1 ${decryptStage > 0 ? 'text-gray-500' : 'text-gray-400'}`}>
                      {decryptStage > 1 ? 'Decryption complete' : decryptStage === 1 ? 'Processing chunks in memory...' : 'Waiting for key derivation'}
                    </p>
                    
                    {/* Active Progress Bar for Stage 2 */}
                    {decryptStage === 1 && (
                      <div className="mt-4 w-full">
                        <div className="flex justify-between text-[11px] font-bold text-gray-500 mb-1.5 uppercase tracking-wider">
                          <span>Progress</span>
                          <span className="text-[#2563EB]">{progress}%</span>
                        </div>
                        <div className="w-full bg-gray-100 rounded-full h-1.5 overflow-hidden">
                          <div className="bg-[#2563EB] h-full rounded-full transition-all duration-300 ease-out" style={{ width: `${progress}%` }}></div>
                        </div>
                      </div>
                    )}
                  </div>
                </div>

                {/* Stage 3: Finalizing Output */}
                <div className="flex items-start gap-4">
                  <div className="bg-white pt-1">
                    {decryptStage > 2 ? (
                      <CheckCircle2 className="w-6 h-6 text-[#10B981]" />
                    ) : decryptStage === 2 ? (
                      <Loader2 className="w-6 h-6 text-[#2563EB] animate-spin" />
                    ) : (
                      <Circle className="w-6 h-6 text-gray-300" />
                    )}
                  </div>
                  <div>
                    <h3 className={`text-[15px] font-bold ${decryptStage > 2 ? 'text-gray-900' : decryptStage === 2 ? 'text-[#2563EB]' : 'text-gray-400'}`}>
                      Finalizing Output
                    </h3>
                    <p className={`text-[13px] mt-1 ${decryptStage > 1 ? 'text-gray-500' : 'text-gray-400'}`}>
                      {decryptStage > 2 ? 'File saved' : decryptStage === 2 ? 'Saving to your device...' : 'Waiting for decryption to complete'}
                    </p>
                  </div>
                </div>
              </div>
            </motion.div>
          )}

          {/* STATE: DONE */}
          {status === 'DONE' && (
            <motion.div key="state-done" variants={fadeVariants} initial="initial" animate="animate" exit="exit" transition={{ duration: 0.2 }} className="text-left">
              <h2 className="text-[20px] font-bold mb-5 pb-3 border-b border-gray-200 text-[#16191f]">
                Unlock Complete
              </h2>
              
              <div className="p-4 bg-[#f2f8f3] border border-[#b2d8b2] mb-6 rounded flex items-start">
                <CheckCircle2 className="w-5 h-5 text-[#1d8102] mr-3 shrink-0 mt-0.5" />
                <div>
                  <h3 className="text-[14px] font-bold text-[#16191f] mb-1">
                    {meta?.isFolder ? 'Folder Extracted Successfully' : 'File Extracted Successfully'}
                  </h3>
                  <p className="text-[13px] text-[#545b64]">
                    {meta?.isFolder
                      ? 'Your encrypted folder has been saved as a .zip file.'
                      : 'Your file has been decrypted and saved to your device.'}
                  </p>
                </div>
              </div>
              
              <button onClick={reset}
                className="w-full py-1.5 px-4 rounded-[2px] bg-white font-bold text-[#16191f] hover:bg-[#f8f8f8] transition-colors border border-[#545b64] shadow-[0_1px_1px_rgba(0,0,0,0.1)]">
                {isEmbedded ? 'Decrypt Again' : 'Unlock Another Vault'}
              </button>
            </motion.div>
          )}

          {/* STATE: ERROR */}
          {status === 'ERROR' && (
            <motion.div key="state-error" variants={fadeVariants} initial="initial" animate="animate" exit="exit" transition={{ duration: 0.2 }} className="text-left">
               <h2 className="text-[20px] font-bold mb-5 pb-3 border-b border-gray-200 text-[#16191f]">
                System Error
              </h2>
              
              <div className="p-4 bg-[#fdf3f1] border border-[#f0b0a3] mb-6 rounded flex items-start">
                <XCircle className="w-5 h-5 text-[#d13212] mr-3 shrink-0 mt-0.5" />
                <div>
                  <h3 className="text-[14px] font-bold text-[#16191f] mb-1">Decryption Failed</h3>
                  <p className="text-[13px] text-[#545b64]">{errorMsg}</p>
                </div>
              </div>

              <button onClick={() => setStatus('IDLE')}
                className="w-full py-1.5 px-4 rounded-[2px] bg-white font-bold text-[#16191f] hover:bg-[#f8f8f8] transition-colors border border-[#545b64] shadow-[0_1px_1px_rgba(0,0,0,0.1)]">
                {isEmbedded ? 'Try Again' : 'Return to Sign In'}
              </button>
            </motion.div>
          )}

          {/* STATE: VIEWING — Secure In-Browser Viewer */}
          {status === 'VIEWING' && viewerBlobUrl && (() => {
            const viewType = getViewerType(meta?.ext || '');
            const cfg = meta?.viewerConfig || {};
            const allowDownload = cfg.allowDownload;
            const allowPrint = cfg.allowPrint;
            const allowCopy = cfg.allowCopy;

            const handleDownload = () => {
              const a = document.createElement('a');
              a.href = viewerBlobUrl;
              a.download = meta?.originalName || 'file';
              document.body.appendChild(a);
              a.click();
              document.body.removeChild(a);
            };

            const handlePrint = () => {
              const iframe = document.createElement('iframe');
              iframe.style.display = 'none';
              iframe.src = viewerBlobUrl;
              document.body.appendChild(iframe);
              iframe.onload = () => { iframe.contentWindow.print(); };
            };

            const isCustomViewer = ['pdf', 'image', 'video', 'audio'].includes(viewType);

            return (
              <motion.div key="state-viewing" variants={fadeVariants} initial="initial" animate="animate" exit="exit" transition={{ duration: 0.2 }} className="text-left w-full">
                {!isCustomViewer && (
                  <div className="flex items-center justify-between mb-4 pb-3 border-b border-gray-200">
                    <h2 className="text-[18px] font-bold text-[#16191f] flex items-center gap-2">
                      <Eye className="w-5 h-5 text-[#2563EB]" /> Secure Viewer
                    </h2>
                    <div className="flex gap-2">
                      {allowPrint && (
                        <button onClick={handlePrint}
                          className="px-3 py-1 text-[12px] font-bold rounded border border-gray-300 text-gray-700 hover:bg-gray-50 transition-colors">
                          Print
                        </button>
                      )}
                      {allowDownload && (
                        <button onClick={handleDownload}
                          className="px-3 py-1 text-[12px] font-bold rounded border border-[#1e40af] bg-[#2563EB] text-white hover:bg-[#1d4ed8] transition-colors flex items-center gap-1">
                          <Download className="w-3.5 h-3.5" /> Download
                        </button>
                      )}
                      <button onClick={reset}
                        className="px-3 py-1 text-[12px] font-bold rounded border border-gray-300 text-gray-600 hover:bg-gray-50 transition-colors">
                        Close
                      </button>
                    </div>
                  </div>
                )}

                {/* PDF */}
                {viewType === 'pdf' && (
                  <SecurePDFViewer 
                    url={viewerBlobUrl} 
                    meta={meta} 
                    config={cfg} 
                    onDownload={handleDownload} 
                    onPrint={handlePrint} 
                    onClose={reset}
                  />
                )}

                {/* Image */}
                {viewType === 'image' && (
                  <SecureImageViewer 
                    url={viewerBlobUrl} 
                    meta={meta} 
                    config={cfg} 
                    onDownload={handleDownload} 
                    onPrint={handlePrint} 
                    onClose={reset}
                  />
                )}

                {/* Video & Audio */}
                {['video', 'audio'].includes(viewType) && (
                  <SecureMediaViewer 
                    blobUrl={viewerBlobUrl}
                    type={viewType}
                    fileName={meta?.originalName}
                    config={cfg}
                    email={null}
                    onClose={reset}
                  />
                )}

                {/* Text / Code */}
                {viewType === 'text' && (
                  <div
                    className="w-full rounded border border-gray-200 bg-gray-50 overflow-auto font-mono text-[12px] text-gray-800 p-4 leading-relaxed whitespace-pre-wrap"
                    style={{ maxHeight: '520px', userSelect: allowCopy ? 'text' : 'none' }}
                  >
                    {textContent}
                  </div>
                )}

                {/* Download Only — unsupported preview format */}
                {viewType === 'download_only' && (
                  <div className="p-6 bg-gray-50 rounded border border-gray-200 flex flex-col items-center gap-4 text-center">
                    <div className="text-5xl">📄</div>
                    <p className="text-[14px] font-medium text-gray-700">{meta?.originalName}</p>
                    <p className="text-[13px] text-gray-500">This file type cannot be previewed in the browser.</p>
                    {allowDownload ? (
                      <button onClick={handleDownload}
                        className="flex items-center gap-2 px-4 py-2 bg-[#2563EB] text-white font-bold text-[13px] rounded border border-[#1e40af] hover:bg-[#1d4ed8] transition-colors">
                        <Download className="w-4 h-4" /> Download File
                      </button>
                    ) : (
                      <p className="text-[13px] text-amber-600 font-medium">⚠️ The sender has restricted downloading this file.</p>
                    )}
                  </div>
                )}

                {!isCustomViewer && (
                  <p className="text-[11px] text-gray-400 mt-3 text-center">
                    🔒 Secure Viewer · {allowDownload ? 'Download allowed' : 'Download restricted'} · {allowPrint ? 'Print allowed' : 'Print restricted'}
                  </p>
                )}
              </motion.div>
            );
          })()}

          </AnimatePresence>
        </div>
      </div>
    </div>
  );
}
