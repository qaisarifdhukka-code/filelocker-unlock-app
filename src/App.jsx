import { useState, useEffect, useCallback } from 'react';
import { argon2id } from 'hash-wasm';
import { motion, AnimatePresence } from 'framer-motion';
import { CheckCircle2, Circle, Loader2, XCircle, AlertCircle, ShieldAlert } from 'lucide-react';
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

// Progress UI elements removed (ProgressRing not needed anymore)

export default function App() {
  const [file,     setFile]     = useState(null);
  const [meta,     setMeta]     = useState(null);
  const [password, setPassword] = useState('');
  const [status,   setStatus]   = useState('IDLE'); // IDLE | DECRYPTING | DONE | ERROR
  const [progress, setProgress] = useState(0);
  const [decryptStage, setDecryptStage] = useState(0); // 0: Key, 1: Chunks, 2: Finalizing
  const [errorMsg, setErrorMsg] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [isEmbedded,   setIsEmbedded]   = useState(false);
  const [branding,     setBranding]     = useState(null);

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

  useEffect(() => { loadEmbeddedVault(); }, [loadEmbeddedVault]);

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
      if (err.name !== 'AbortError') setErrorMsg(err.message);
    }
  };

  // ── Decrypt vault ──────────────────────────────────────────────────────────
  const decryptVault = async () => {
    if (!password) { setErrorMsg('Please enter a password.'); return; }

    try {
      setStatus('DECRYPTING');
      setProgress(0);
      setDecryptStage(0);
      setErrorMsg('');

      // Derive key with Argon2id
      const salt = hexToBytes(meta.salt);
      const keyArray = await argon2id({
        password: password,
        salt: salt,
        parallelism: 1,
        iterations: 3,
        memorySize: 65536, // 64MB
        hashLength: 32,
        outputType: 'binary'
      });
      
      const key = await crypto.subtle.importKey(
        'raw', 
        keyArray, 
        { name: 'AES-GCM' }, 
        false, 
        ['decrypt']
      );
      
      setPassword('');

      // Prompt save location or prepare fallback
      let writable;
      let chunks = [];
      const isFallback = !window.showSaveFilePicker;

      if (!isFallback) {
        const saveFh = await window.showSaveFilePicker({ suggestedName: meta.originalName });
        writable = await saveFh.createWritable();
      }

      const dataStart = meta.dataStart;
      const dataSize  = file.size - dataStart;
      let   offset    = dataStart;
      
      setDecryptStage(1);

      while (offset < file.size) {
        const chunkBuf = await file.slice(offset, offset + CHUNK_ENC).arrayBuffer();
        if (chunkBuf.byteLength < 28) break; // too small to be a valid chunk

        const iv       = chunkBuf.slice(0, 12);
        const tag      = chunkBuf.slice(12, 28);
        const data     = chunkBuf.slice(28);

        // WebCrypto expects [ciphertext || tag]
        const combined = new Uint8Array(data.byteLength + tag.byteLength);
        combined.set(new Uint8Array(data), 0);
        combined.set(new Uint8Array(tag), data.byteLength);

        const dec = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, combined);
        if (isFallback) chunks.push(new Uint8Array(dec));
        else await writable.write(dec);

        offset += chunkBuf.byteLength;
        setProgress(Math.min(100, Math.round(((offset - dataStart) / dataSize) * 100)));
      }

      setDecryptStage(2);

      if (isFallback) {
        const blob = new Blob(chunks);
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = meta.originalName;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
      } else {
        await writable.close();
      }
      setStatus('DONE');
    } catch (err) {
      console.error(err);
      setStatus('ERROR');
      setErrorMsg(
        err.message.includes('auth') || err.message.includes('operation')
          ? 'Invalid password or corrupted vault file.'
          : err.message
      );
    }
  };

  const reset = () => {
    setPassword('');
    setStatus('IDLE');
    setProgress(0);
    setDecryptStage(0);
    setErrorMsg('');
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
    <div className="min-h-screen flex flex-col md:flex-row w-full bg-white">
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
            Your sensitive files, encrypted to military standards and protected completely offline.
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
          {/* STATE: IDLE — no file selected */}
          {status === 'IDLE' && !file && (
            <motion.div key="state-no-file" variants={fadeVariants} initial="initial" animate="animate" exit="exit" transition={{ duration: 0.2 }}>
              <h2 className="text-[20px] font-bold mb-5 pb-3 border-b border-gray-200 text-[#16191f] flex items-center">
                {branding?.firmName ? branding.firmName : "Vault Unlock"} <ShieldAlert className="w-[18px] h-[18px] ml-2 text-[#0073bb] stroke-[2px]" />
              </h2>
              
              <div className="mb-6">
                <label className="block text-[14px] font-medium text-[#16191f] mb-1">
                  Vault Drive location <span className="text-[#0073bb] font-normal cursor-help hover:underline">(Where is it?)</span>
                </label>
                <div className="text-[13px] text-[#545b64]">
                  Open the <strong>Vault_Data</strong> folder on this USB drive and select your <code>.vault</code> file to decrypt it.
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
                <div className="w-full px-3 py-1.5 text-[14px] bg-[#f2f3f3] border border-[#aab7b8] rounded-[2px] text-[#545b64] font-mono truncate">
                  {meta?.originalName}
                </div>
              </div>

              <div className="mb-4">
                <label className="block text-[14px] font-medium text-[#16191f] mb-1">Password</label>
                <input
                  type={showPassword ? "text" : "password"}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && decryptVault()}
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

              <button onClick={decryptVault}
                className="w-full py-1.5 px-4 rounded-[2px] bg-[#2563EB] font-bold text-white hover:bg-[#1d4ed8] transition-colors border border-[#1e40af] shadow-[0_1px_1px_rgba(0,0,0,0.1)]">
                Unlock &amp; Download
              </button>

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
          </AnimatePresence>
        </div>
      </div>
    </div>
  );
}
