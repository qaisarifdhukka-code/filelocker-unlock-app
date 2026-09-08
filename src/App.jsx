import React, { useState, useEffect, useCallback, useRef } from 'react';
import { argon2id } from 'hash-wasm';
import { motion, AnimatePresence } from 'framer-motion';
import { ShieldAlert, AlertCircle, Loader2, Eye, EyeOff, Download, FileText, CheckCircle2, Circle, XCircle, Copy } from 'lucide-react';
import SecurePDFViewer from './components/SecurePDFViewer';
import SecureImageViewer from './components/SecureImageViewer';
import { SecureMediaViewer } from './components/SecureMediaViewer';
import { APP_CONFIG } from './config';
import Argon2Worker from './worker.js?worker&inline';
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
  const [isDragging, setIsDragging] = useState(false);
  
  // OTP Verification States
  const [email, setEmail] = useState('');
  const [otp, setOtp] = useState('');
  const [otpSending, setOtpSending] = useState(false);
  const [otpVerifying, setOtpVerifying] = useState(false);
  const [copiedLink, setCopiedLink] = useState(false);

  // Prevent accidental close during decryption
  useEffect(() => {
    const handleBeforeUnload = (e) => {
      if (status === 'DECRYPTING' || isCloudLoading) {
        e.preventDefault();
        e.returnValue = '';
      }
    };
    window.addEventListener('beforeunload', handleBeforeUnload);
    return () => window.removeEventListener('beforeunload', handleBeforeUnload);
  }, [status, isCloudLoading]);

  // References to OPFS files for cleanup
  const activeOpfsHandles = React.useRef([]);
  
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

  const hasAttemptedCloudLoad = useRef(false);

  // ── Auto-load cloud vault (Secure Link Mode) ──────────────────────────────
  const loadCloudVault = useCallback(async () => {
    if (window.location.protocol === 'file:') return false;
    
    // URL pattern: /:firmSlug/:linkId
    const pathParts = window.location.pathname.split('/').filter(Boolean);
    if (pathParts.length < 2) return false;

    if (hasAttemptedCloudLoad.current) return false;
    hasAttemptedCloudLoad.current = true;

    const linkId = pathParts[pathParts.length - 1];
    
    try {
      setIsCloudLoading(true);
      setErrorMsg('');
      
      // The API endpoint is POST /api/links/:link_id/download
      const API_BASE = APP_CONFIG.API_URL;
      const sessionToken = sessionStorage.getItem(`filelocker_session_${linkId}`);
      const headers = {};
      if (sessionToken) headers['Authorization'] = `Bearer ${sessionToken}`;

      // First check metadata to see if OTP is required
      const metaRes = await fetch(`${API_BASE}/api/links/${linkId}`);
      if (!metaRes.ok) throw new Error('Secure link not found.');
      const linkMeta = await metaRes.json();
      
      if (linkMeta.status === 'expired') {
        throw new Error('Link is expired.');
      }
      if (linkMeta.status === 'consumed') {
        // Technically still downloadable for 6 hours if session is valid, which backend handles
      }

      if (linkMeta.require_email_otp && !sessionToken) {
        setIsCloudLoading(false);
        setStatus('EMAIL_PROMPT');
        return true;
      }

      // Use a HEAD request to get the content-length without downloading the body!
      const initialRes = await fetch(`${API_BASE}/api/links/${linkId}/download`, {
        method: 'HEAD',
        headers
      });

      if (!initialRes.ok) {
        let msg = 'Failed to download secure vault.';
        if (initialRes.status === 403) {
          msg = 'Link is expired, consumed, or email verification is required.';
          if (linkMeta.require_email_otp && !sessionToken) {
            setIsCloudLoading(false);
            setStatus('EMAIL_PROMPT');
            return true;
          }
        } else if (initialRes.status === 404) {
          msg = 'Secure link not found.';
        }
        throw new Error(msg);
      }

      const contentLengthStr = initialRes.headers.get('content-length');
      const totalBytes = contentLengthStr ? parseInt(contentLengthStr, 10) : 0;
      
      const LARGE_FILE_THRESHOLD = 150 * 1024 * 1024; // 150 MB
      let vaultFile;

      if (totalBytes > LARGE_FILE_THRESHOLD && navigator.storage) {
        // Stream to OPFS in chunks with retries
        const root = await navigator.storage.getDirectory();
        const handle = await root.getFileHandle(`download_${Date.now()}.vault`, { create: true });
        trackOpfsHandle(handle);
        const writable = await handle.createWritable();
        
        const CHUNK_SIZE = 10 * 1024 * 1024; // 10MB chunks
        let offset = 0;
        
        const fetchChunk = async (start, end, retries = 3) => {
          for (let i = 0; i < retries; i++) {
            try {
              const reqHeaders = { 'Range': `bytes=${start}-${end}` };
              if (sessionToken) reqHeaders['Authorization'] = `Bearer ${sessionToken}`;
              const res = await fetch(`${API_BASE}/api/links/${linkId}/download`, {
                method: 'POST', // Use POST for range request as required by backend
                headers: reqHeaders
              });
              if (!res.ok) throw new Error(`HTTP ${res.status}`);
              return new Uint8Array(await res.arrayBuffer());
            } catch (err) {
              if (i === retries - 1) throw err;
              await new Promise(r => setTimeout(r, 1000 * (i + 1)));
            }
          }
        };

        while (offset < totalBytes) {
          const end = Math.min(offset + CHUNK_SIZE - 1, totalBytes - 1);
          const chunkData = await fetchChunk(offset, end);
          await writable.write(chunkData);
          offset += chunkData.length;
          setDownloadProgress(Math.round((offset / totalBytes) * 100));
        }
        await writable.close();
        vaultFile = await handle.getFile();
      } else {
        // Standard in-memory blob for small files (we still need to actually download it since we used HEAD)
        const fullRes = await fetch(`${API_BASE}/api/links/${linkId}/download`, { 
          method: 'POST',
          headers
        });
        
        if (!fullRes.ok) {
          let msg = 'Failed to download secure vault.';
          try { const errData = await fullRes.json(); if (errData.error) msg = errData.error; } catch(e) {}
          throw new Error(msg);
        }

        const blob = await fullRes.blob();
        vaultFile = new File([blob], 'Secure_Delivery.vault', { type: 'application/octet-stream' });
      }
      
      // Parse the fixed header
      const fixedBuf = await vaultFile.slice(0, HEADER_BASE + META_LEN_SIZE).arrayBuffer();
      const fixedArr = new Uint8Array(fixedBuf);
      for (let i = 0; i < 4; i++) {
        if (fixedArr[i] !== MAGIC_EXPECTED[i]) throw new Error('Not a valid FileLocker file.');
      }
      const metaLen = new DataView(fixedBuf).getUint32(HEADER_BASE, true);
      
      // Parse metadata
      const metaStart = HEADER_BASE + META_LEN_SIZE;
      const metaBuf   = await vaultFile.slice(metaStart, metaStart + metaLen).arrayBuffer();
      const parsedMeta = JSON.parse(new TextDecoder().decode(metaBuf));
      const dataStart  = metaStart + metaLen + NONCE_SIZE;

      setFile(vaultFile);
      setMeta({ ...parsedMeta, dataStart });
      setBranding(parsedMeta.branding || null);

      // ── Auto-Key Detection (OTP-Only Mode) ─────────────────────────────────
      // The key might be in the URL hash (first visit) or sessionStorage (refresh)
      const hash = window.location.hash;
      const keyMatch = hash.match(/[#&]key=([A-Za-z0-9_-]+)/);
      let autoKey = null;

      if (keyMatch) {
        autoKey = keyMatch[1];
        // Cache the key in sessionStorage so it survives page refreshes
        sessionStorage.setItem(`filelocker_autokey_${linkId}`, autoKey);
        // Remove the key from the URL bar immediately for security.
        history.replaceState(null, '', window.location.pathname + window.location.search);
      } else {
        autoKey = sessionStorage.getItem(`filelocker_autokey_${linkId}`);
      }

      if (autoKey) {
        // Bug Fix: Set these immediately before state settles to prevent the password UI from flickering
        setIsDeriving(true);
        setStatus('DECRYPTING');
        // Trigger auto-decryption. Pass the key directly; bypass password prompt entirely.
        setTimeout(() => decryptVaultWithKey(autoKey, parsedMeta, dataStart, vaultFile), 50);
      }
      
    } catch (err) {
      setErrorMsg(err.message);
    } finally {
      setIsCloudLoading(false);
    }
    return true;
  }, []);

  useEffect(() => {
    if (!loadEmbeddedVault()) {
      loadCloudVault();
    }
  }, [loadEmbeddedVault, loadCloudVault]);

  const processSelectedVault = async (selected) => {
    try {
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
      if (err.name !== 'AbortError') setErrorMsg(err.message);
    }
  };

  useEffect(() => {
    const handleDragOver = (e) => {
      e.preventDefault();
      if (e.dataTransfer.types.includes('Files')) setIsDragging(true);
    };
    const handleDragLeave = (e) => {
      e.preventDefault();
      if (e.clientX === 0 && e.clientY === 0) setIsDragging(false);
    };
    const handleDrop = async (e) => {
      e.preventDefault();
      setIsDragging(false);
      if (status !== 'IDLE' || file || isCloudLoading) return;

      const droppedFiles = e.dataTransfer.files;
      if (droppedFiles.length > 0) {
        const selected = droppedFiles[0];
        if (selected.name.endsWith('.vault')) {
          await processSelectedVault(selected);
        } else {
          setErrorMsg('Please drop a valid .vault file.');
        }
      }
    };

    window.addEventListener('dragover', handleDragOver);
    window.addEventListener('dragleave', handleDragLeave);
    window.addEventListener('drop', handleDrop);

    return () => {
      window.removeEventListener('dragover', handleDragOver);
      window.removeEventListener('dragleave', handleDragLeave);
      window.removeEventListener('drop', handleDrop);
    };
  }, [status, file, isCloudLoading]);

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
      await processSelectedVault(selected);
    } catch (err) {
      if (err.name !== 'AbortError') setErrorMsg(err.message);
    }
  };

  // ── Core Decryption Pipeline ────────────────────────────────────────────────
  // Called by both decryptVault (password UI) and decryptVaultWithKey (auto-key / OTP-only).
  // `passwordStr` is the plaintext password string. `targetFile` and `targetMeta` default
  // to the current React state values so existing callers require no changes.
  const runDecryptionPipeline = async (passwordStr, targetFile, targetMeta) => {
    const resolvedFile = targetFile || file;
    const resolvedMeta = targetMeta || meta;
    if (!resolvedFile || !resolvedMeta) throw new Error('No vault loaded.');

    setIsDeriving(true);
    setErrorMsg('');

    // Derive key with Argon2id using a Web Worker to prevent UI freezing
    const salt = hexToBytes(resolvedMeta.salt);
    const keyArray = await new Promise((resolve, reject) => {
      const worker = new Argon2Worker();
      worker.onmessage = (e) => {
        if (e.data.success) resolve(e.data.keyArray);
        else reject(new Error(e.data.error));
        worker.terminate();
      };
      worker.onerror = () => { reject(new Error('Key derivation failed')); worker.terminate(); };
      worker.postMessage({ password: passwordStr, salt });
    });

    const key = await crypto.subtle.importKey('raw', keyArray, { name: 'AES-GCM' }, false, ['decrypt']);

    let downloadName = resolvedMeta.originalName;
    if (resolvedMeta.encryptedName) {
      try {
        const encNameBuf = hexToBytes(resolvedMeta.encryptedName);
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

    // PRE-FLIGHT CHECK: Attempt to decrypt the first chunk to verify the password/key
    const dataStart = resolvedMeta.dataStart;
    const dataSize  = resolvedFile.size - dataStart;
    const firstChunkBuf = await resolvedFile.slice(dataStart, dataStart + CHUNK_ENC).arrayBuffer();
    if (firstChunkBuf.byteLength >= 28) {
      const iv = firstChunkBuf.slice(0, 12);
      const tag = firstChunkBuf.slice(12, 28);
      const data = firstChunkBuf.slice(28);
      const combined = new Uint8Array(data.byteLength + tag.byteLength);
      combined.set(new Uint8Array(data), 0);
      combined.set(new Uint8Array(tag), data.byteLength);
      await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, combined);
    }

    setPassword('');

    // Authorize session with server (increments view_count exactly once)
    if (!isEmbedded && window.location.protocol !== 'file:') {
      const pathParts = window.location.pathname.split('/').filter(Boolean);
      if (pathParts.length >= 2) {
        const linkId = pathParts[pathParts.length - 1];
        const API_BASE = APP_CONFIG.API_URL;
        const sessionHeaders = { 'Content-Type': 'application/json' };
        const existingToken = sessionStorage.getItem(`filelocker_session_${linkId}`);
        if (existingToken) sessionHeaders['Authorization'] = `Bearer ${existingToken}`;
        const sessionRes = await fetch(`${API_BASE}/api/links/${linkId}/session`, {
          method: 'POST',
          headers: sessionHeaders
        });
        if (!sessionRes.ok) {
          let msg = 'Failed to authorize session.';
          try { const errData = await sessionRes.json(); if (errData.error) msg = errData.error; } catch(e) {}
          throw new Error(msg);
        }
        const sessionData = await sessionRes.json();
        if (sessionData.sessionToken) {
          sessionStorage.setItem(`filelocker_session_${linkId}`, sessionData.sessionToken);
        }
      }
    }

    setIsDeriving(false);
    setStatus('DECRYPTING');
    setProgress(0);
    setDecryptStage(1);

    // In secure_view mode, ALWAYS collect into memory
    const isSecureView = resolvedMeta.viewerConfig?.mode === 'secure_view';
    let writable;
    let chunks = [];
    const isFallback = !window.showSaveFilePicker || isSecureView;
    const LARGE_FILE_THRESHOLD = 150 * 1024 * 1024;
    const useOPFSFallback = isFallback && (resolvedFile.size >= LARGE_FILE_THRESHOLD) && navigator.storage;
    let opfsDecryptedHandle = null;

    if (!isFallback) {
      try {
        const saveFh = await window.showSaveFilePicker({ suggestedName: downloadName });
        writable = await saveFh.createWritable();
      } catch (err) {
        throw new Error(`Failed to save file: ${err.message}.`);
      }
    } else if (useOPFSFallback) {
      try {
        const root = await navigator.storage.getDirectory();
        opfsDecryptedHandle = await root.getFileHandle(`decrypted_${Date.now()}_${downloadName}`, { create: true });
        trackOpfsHandle(opfsDecryptedHandle);
        writable = await opfsDecryptedHandle.createWritable();
      } catch (err) {
        throw new Error(`Secure View for large files requires browser local storage (OPFS). (${err.message})`);
      }
    }

    let offset = dataStart;
    while (offset < resolvedFile.size) {
      const chunkBuf = await resolvedFile.slice(offset, offset + CHUNK_ENC).arrayBuffer();
      if (chunkBuf.byteLength < 28) break;
      const iv = chunkBuf.slice(0, 12);
      const tag = chunkBuf.slice(12, 28);
      const data = chunkBuf.slice(28);
      const combined = new Uint8Array(data.byteLength + tag.byteLength);
      combined.set(new Uint8Array(data), 0);
      combined.set(new Uint8Array(tag), data.byteLength);
      const dec = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, combined);
      if (!isFallback) await writable.write(dec);
      else if (useOPFSFallback) await writable.write(dec);
      else chunks.push(new Uint8Array(dec));
      offset += chunkBuf.byteLength;
      setProgress(Math.min(100, Math.round(((offset - dataStart) / dataSize) * 100)));
    }

    setDecryptStage(2);

    if (isSecureView) {
      const mimeType = getMimeType(resolvedMeta.ext);
      let blob;
      if (useOPFSFallback) { await writable.close(); blob = await opfsDecryptedHandle.getFile(); }
      else { blob = new Blob(chunks, { type: mimeType }); }
      const url = URL.createObjectURL(blob);
      const viewType = getViewerType(resolvedMeta.ext);
      if (viewType === 'text') { const text = await blob.text(); setTextContent(text); }
      setViewerBlobUrl(url);
      setStatus('VIEWING');
    } else if (isFallback) {
      let blob;
      if (useOPFSFallback) { await writable.close(); blob = await opfsDecryptedHandle.getFile(); }
      else { blob = new Blob(chunks); }
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = downloadName;
      document.body.appendChild(a); a.click(); document.body.removeChild(a);
      URL.revokeObjectURL(url);
      setStatus('DONE');
    } else {
      await writable.close();
      setStatus('DONE');
    }
  };

  // ── Auto-decrypt for OTP-only links (called with auto-key from URL hash) ─────
  const decryptVaultWithKey = async (autoKey, overrideMeta, overrideDataStart, overrideFile) => {
    const resolvedMeta = overrideMeta ? { ...overrideMeta, dataStart: overrideDataStart } : meta;
    const resolvedFile = overrideFile || file;
    try {
      await runDecryptionPipeline(autoKey, resolvedFile, resolvedMeta);
    } catch (err) {
      console.error(err);
      setIsDeriving(false);
      setStatus('ERROR');
      setErrorMsg('Auto-decryption failed. The link may be corrupted or the key was stripped. Please ask the sender to resend the full link including the #key= portion.');
    }
  };

  // ── Decrypt vault (password UI path) ───────────────────────────────────────
  const decryptVault = async () => {
    if (!password) { setErrorMsg('Please enter a password.'); return; }
    if (isDeriving) return;

    try {
      await runDecryptionPipeline(password, file, meta);
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
    setEmail('');
    setOtp('');
  };

  const handleSendOtp = async (e) => {
    if (e) e.preventDefault();
    if (!email) { setErrorMsg('Please enter your email address.'); return; }
    
    const pathParts = window.location.pathname.split('/').filter(Boolean);
    const linkId = pathParts[pathParts.length - 1];
    
    try {
      setOtpSending(true);
      setErrorMsg('');
      const res = await fetch(`${APP_CONFIG.API_URL}/api/links/${linkId}/send-otp`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Failed to send verification code.');
      
      setStatus('OTP_PROMPT');
    } catch (err) {
      setErrorMsg(err.message);
    } finally {
      setOtpSending(false);
    }
  };

  const handleVerifyOtp = async (e) => {
    if (e) e.preventDefault();
    if (!otp) { setErrorMsg('Please enter the verification code.'); return; }
    
    const pathParts = window.location.pathname.split('/').filter(Boolean);
    const linkId = pathParts[pathParts.length - 1];
    
    try {
      setOtpVerifying(true);
      setErrorMsg('');
      const res = await fetch(`${APP_CONFIG.API_URL}/api/links/${linkId}/verify-otp`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, otp })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Invalid verification code.');
      
      // Save the OTP token
      sessionStorage.setItem(`filelocker_session_${linkId}`, data.otpToken);
      
      // Resume loading the cloud vault now that we have OTP access
      setStatus('IDLE');
      setIsCloudLoading(true); // this gives visual feedback before the async fn finishes
      setTimeout(() => {
        hasAttemptedCloudLoad.current = false;
        loadCloudVault();
      }, 0);
    } catch (err) {
      setErrorMsg(err.message);
    } finally {
      setOtpVerifying(false);
    }
  };

  const handleCopyLink = async () => {
    try {
      const pathParts = window.location.pathname.split('/').filter(Boolean);
      const linkId = pathParts[pathParts.length - 1];
      const autoKey = sessionStorage.getItem(`filelocker_autokey_${linkId}`);
      let url = window.location.href.split('#')[0];
      if (autoKey) url += `#key=${autoKey}`;
      await navigator.clipboard.writeText(url);
      setCopiedLink(true);
      setTimeout(() => setCopiedLink(false), 2000);
    } catch(err) {
      console.error('Failed to copy link:', err);
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
        
        <AnimatePresence>
          {isDragging && status === 'IDLE' && !file && !isCloudLoading && (
            <motion.div 
              initial={{ opacity: 0 }} 
              animate={{ opacity: 1 }} 
              exit={{ opacity: 0 }}
              className="absolute inset-0 z-50 bg-white/80 backdrop-blur-sm border-4 border-dashed border-[#2563EB] flex flex-col items-center justify-center m-4 rounded-xl"
            >
              <div className="bg-[#2563EB] text-white p-4 rounded-full mb-4 shadow-lg">
                <Download className="w-8 h-8" />
              </div>
              <h3 className="text-xl font-bold text-gray-900">Drop Vault File Here</h3>
              <p className="text-gray-500 mt-2 text-sm">Release to unlock</p>
            </motion.div>
          )}
        </AnimatePresence>

        <div className="w-full max-w-sm text-left mx-auto">
          <div className="flex md:hidden mb-10">
            {branding?.logoBase64 ? (
              <img src={branding.logoBase64} alt={branding.firmName || "Firm Logo"} className="h-[40px] w-auto max-w-[200px] object-contain" />
            ) : (
              <img src={logoUrl} alt="FileLocker Logo" className="h-[36px] w-auto" />
            )}
          </div>

          <AnimatePresence mode="wait">
          {/* STATE: IDLE — no file selected */}
          {status === 'IDLE' && !file && (
            <motion.div key="state-no-file" variants={fadeVariants} initial="initial" animate="animate" exit="exit" transition={{ duration: 0.2 }}>
              <h2 className="text-[20px] font-bold mb-5 pb-3 border-b border-gray-200 text-[#16191f] flex items-center">
                {branding?.firmName ? branding.firmName : "Vault Unlock"} <ShieldAlert className="w-[18px] h-[18px] ml-2 text-[#0073bb] stroke-[2px]" />
              </h2>
              
              {isCloudLoading ? (
                <div className="flex flex-col items-center justify-center p-8 bg-[#f8f9fa] border rounded-[2px] mb-6 text-center" style={{ borderColor: '#eaeded' }}>
                  <Loader2 className="w-8 h-8 text-[#0073bb] animate-spin mb-3" />
                  <h3 className="text-[14px] font-bold text-[#16191f]">Downloading Secure Vault</h3>
                  <p className="text-[13px] mt-1 text-[#545b64]">
                    {downloadProgress > 0 
                      ? `Fetching your encrypted delivery... ${downloadProgress}%` 
                      : `Fetching your encrypted delivery from the cloud...`}
                  </p>
                  {downloadProgress > 0 && (
                    <div className="w-full max-w-[200px] bg-gray-200 rounded-full h-1.5 mt-3 overflow-hidden">
                      <div className="bg-[#0073bb] h-full rounded-full transition-all duration-300" style={{ width: `${downloadProgress}%` }}></div>
                    </div>
                  )}
                </div>
              ) : (
                <>
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
                </>
              )}
              
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

          {/* STATE: IDLE — file selected, enter password */}
          {status === 'IDLE' && file && (
            <motion.div key="state-password" variants={fadeVariants} initial="initial" animate="animate" exit="exit" transition={{ duration: 0.2 }}>
              
              <h2 className="text-[20px] font-bold mb-5 pb-3 border-b border-gray-200 text-[#16191f] flex items-center">
                {branding?.firmName ? branding.firmName : "Vault Unlock"} <ShieldAlert className="w-[18px] h-[18px] ml-2 text-[#0073bb] stroke-[2px]" />
              </h2>

              <div className="mb-4">
                <label className="block text-[14px] font-medium text-[#16191f] mb-1">
                  Selected vault alias{!isEmbedded && (
                    <span className="text-[#0073bb] font-normal hover:underline cursor-pointer ml-1" onClick={reset}>(Change?)</span>
                  )}
                </label>
                <div className="w-full px-3 py-1.5 text-[14px] bg-[#f2f3f3] border border-[#aab7b8] rounded-[2px] text-[#545b64] font-mono truncate flex items-center">
                  <FileText className="w-4 h-4 mr-2 shrink-0 text-[#0073bb]" />
                  {meta?.originalName}
                </div>
              </div>

              <div className="mb-4">
                <label className="block text-[14px] font-medium text-[#16191f] mb-1">Password</label>
                <motion.div 
                  className="relative"
                  animate={errorMsg ? { x: [-10, 10, -10, 10, 0] } : {}}
                  transition={{ duration: 0.4 }}
                >
                  <input
                    autoComplete="off" autoCorrect="off" autoCapitalize="none" spellCheck="false"
                    type={showPassword ? "text" : "password"}
                    value={password}
                    onChange={(e) => { setPassword(e.target.value); setErrorMsg(''); }}
                    onKeyDown={(e) => e.key === 'Enter' && decryptVault()}
                    className={`w-full pl-3 pr-10 py-1.5 text-[14px] bg-white border ${errorMsg ? 'border-[#d13212] focus:border-[#d13212] focus:shadow-[0_0_0_1px_#d13212]' : 'border-[#aab7b8] focus:border-[#0073bb] focus:shadow-[0_0_0_1px_#0073bb]'} rounded-[2px] focus:outline-none transition-shadow`} />
                  <button 
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-2.5 top-[7px] text-[#545b64] hover:text-[#16191f] focus:outline-none"
                  >
                    {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </motion.div>
              </div>

              <div className="mb-6 flex justify-end">
                {meta?.hint && (
                  <span className="text-[13px] text-[#0073bb] hover:underline cursor-help" title={meta.hint}>Having trouble?</span>
                )}
              </div>

              <button onClick={decryptVault} disabled={isDeriving}
                className={`w-full py-1.5 px-4 rounded-[2px] font-bold text-white transition-colors border shadow-[0_1px_1px_rgba(0,0,0,0.1)] flex items-center justify-center ${isDeriving ? 'bg-blue-400 border-blue-400 cursor-wait' : 'bg-[#2563EB] hover:bg-[#1d4ed8] border-[#1e40af]'}`}>
                {isDeriving ? (
                  <><Loader2 className="w-4 h-4 mr-2 animate-spin" /> Verifying...</>
                ) : (
                  'Unlock & Download'
                )}
              </button>
              
              <div className="mt-4 flex items-start gap-2 text-[12px] text-gray-500 bg-[#f8f9fa] p-3 rounded border border-gray-200">
                <ShieldAlert className="w-4 h-4 text-[#10B981] shrink-0 mt-0.5" />
                <span><strong>100% Local Decryption:</strong> Your password is never sent to our servers. All decryption happens securely within this browser tab.</span>
              </div>

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
              
              {(!meta?.maxViews || meta.maxViews > 1) && !isEmbedded && (
                <button onClick={handleCopyLink}
                  className="w-full py-1.5 px-4 mb-3 rounded-[2px] bg-[#f8f9fa] font-bold text-[#16191f] hover:bg-[#eaeded] transition-colors border border-[#aab7b8] shadow-[0_1px_1px_rgba(0,0,0,0.1)] flex items-center justify-center">
                  {copiedLink ? <CheckCircle2 className="w-4 h-4 mr-2 text-green-600" /> : <Copy className="w-4 h-4 mr-2" />}
                  {copiedLink ? 'Copied to Clipboard!' : 'Copy Secure Link to Share'}
                </button>
              )}
              
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

          {/* STATE: EMAIL_PROMPT */}
          {status === 'EMAIL_PROMPT' && (
            <motion.div key="state-email" variants={fadeVariants} initial="initial" animate="animate" exit="exit" transition={{ duration: 0.2 }}>
              <h2 className="text-[20px] font-bold mb-5 pb-3 border-b border-gray-200 text-[#16191f] flex items-center">
                {branding?.firmName ? branding.firmName : "Vault Unlock"} <ShieldAlert className="w-[18px] h-[18px] ml-2 text-[#0073bb] stroke-[2px]" />
              </h2>
              <div className="mb-6">
                <label className="block text-[14px] font-medium text-[#16191f] mb-1">Verify your email</label>
                <p className="text-[13px] text-[#545b64] mb-3">Enter the email address this secure delivery was sent to.</p>
                <form onSubmit={handleSendOtp}>
                  <input
                    type="email"
                    value={email}
                    onChange={(e) => { setEmail(e.target.value); setErrorMsg(''); }}
                    placeholder="name@example.com"
                    required
                    className={`w-full px-3 py-1.5 text-[14px] bg-white border ${errorMsg ? 'border-[#d13212] focus:border-[#d13212] focus:shadow-[0_0_0_1px_#d13212]' : 'border-[#aab7b8] focus:border-[#0073bb] focus:shadow-[0_0_0_1px_#0073bb]'} rounded-[2px] focus:outline-none transition-shadow mb-4`}
                  />
                  <button type="submit" disabled={otpSending}
                    className={`w-full py-1.5 px-4 rounded-[2px] font-bold text-white transition-colors border shadow-[0_1px_1px_rgba(0,0,0,0.1)] flex items-center justify-center ${otpSending ? 'bg-blue-400 border-blue-400 cursor-wait' : 'bg-[#2563EB] hover:bg-[#1d4ed8] border-[#1e40af]'}`}>
                    {otpSending ? <><Loader2 className="w-4 h-4 mr-2 animate-spin" /> Sending...</> : 'Send Verification Code'}
                  </button>
                </form>
              </div>
              {errorMsg && (
                <div className="mt-4 p-3 rounded-[2px] text-[13px] border-l-4 border-[#d13212] bg-[#fdf3f1] text-[#d13212] flex items-start">
                  <AlertCircle className="w-4 h-4 mr-2 mt-0.5 shrink-0" />
                  <span>{errorMsg}</span>
                </div>
              )}
            </motion.div>
          )}

          {/* STATE: OTP_PROMPT */}
          {status === 'OTP_PROMPT' && (
            <motion.div key="state-otp" variants={fadeVariants} initial="initial" animate="animate" exit="exit" transition={{ duration: 0.2 }}>
              <h2 className="text-[20px] font-bold mb-5 pb-3 border-b border-gray-200 text-[#16191f] flex items-center">
                {branding?.firmName ? branding.firmName : "Vault Unlock"} <ShieldAlert className="w-[18px] h-[18px] ml-2 text-[#0073bb] stroke-[2px]" />
              </h2>
              <div className="mb-6">
                <label className="block text-[14px] font-medium text-[#16191f] mb-1">Enter Verification Code</label>
                <p className="text-[13px] text-[#545b64] mb-3">We sent a 6-digit code to <strong>{email}</strong>.</p>
                <form onSubmit={handleVerifyOtp}>
                  <input
                    type="text"
                    value={otp}
                    onChange={(e) => { setOtp(e.target.value.replace(/[^0-9]/g, '')); setErrorMsg(''); }}
                    placeholder="123456"
                    maxLength={6}
                    required
                    className={`w-full px-3 py-1.5 text-[14px] font-mono tracking-widest text-center bg-white border ${errorMsg ? 'border-[#d13212] focus:border-[#d13212] focus:shadow-[0_0_0_1px_#d13212]' : 'border-[#aab7b8] focus:border-[#0073bb] focus:shadow-[0_0_0_1px_#0073bb]'} rounded-[2px] focus:outline-none transition-shadow mb-4`}
                  />
                  <button type="submit" disabled={otpVerifying || otp.length !== 6}
                    className={`w-full py-1.5 px-4 rounded-[2px] font-bold text-white transition-colors border shadow-[0_1px_1px_rgba(0,0,0,0.1)] flex items-center justify-center ${(otpVerifying || otp.length !== 6) ? 'bg-blue-400 border-blue-400 cursor-not-allowed' : 'bg-[#2563EB] hover:bg-[#1d4ed8] border-[#1e40af]'}`}>
                    {otpVerifying ? <><Loader2 className="w-4 h-4 mr-2 animate-spin" /> Verifying...</> : 'Verify & Continue'}
                  </button>
                </form>
                <div className="mt-4 text-center">
                  <button onClick={handleSendOtp} disabled={otpSending} className="text-[13px] text-[#0073bb] hover:underline focus:outline-none">
                    {otpSending ? 'Resending...' : 'Resend Code'}
                  </button>
                </div>
              </div>
              {errorMsg && (
                <div className="mt-4 p-3 rounded-[2px] text-[13px] border-l-4 border-[#d13212] bg-[#fdf3f1] text-[#d13212] flex items-start">
                  <AlertCircle className="w-4 h-4 mr-2 mt-0.5 shrink-0" />
                  <span>{errorMsg}</span>
                </div>
              )}
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
                      {(!meta?.maxViews || meta.maxViews > 1) && !isEmbedded && (
                        <button onClick={handleCopyLink}
                          className="px-3 py-1 text-[12px] font-bold rounded border border-gray-300 text-gray-700 hover:bg-gray-50 transition-colors flex items-center gap-1">
                          {copiedLink ? <CheckCircle2 className="w-3.5 h-3.5 text-green-600" /> : <Copy className="w-3.5 h-3.5" />}
                          {copiedLink ? 'Copied' : 'Copy Link'}
                        </button>
                      )}
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
