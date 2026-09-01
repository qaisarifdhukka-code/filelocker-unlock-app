import React, { useState, useEffect } from 'react';
import { ZoomIn, ZoomOut, Maximize, RotateCw, Download, Printer } from 'lucide-react';

export default function SecureImageViewer({ url, meta, config, onDownload, onPrint, onClose }) {
  const [scale, setScale] = useState(1.0);
  const [rotation, setRotation] = useState(0);
  const [isFullscreen, setIsFullscreen] = useState(false);

  const now = new Date();
  const dateStr = now.toLocaleDateString() + ' ' + now.toLocaleTimeString();
  const watermarkTitle = config?.customWatermark ? config.customWatermark : 'CONFIDENTIAL';
  const watermarkText = meta?.recipientEmail ? `${watermarkTitle} - ${meta.recipientEmail}` : watermarkTitle;

  const allowDownload = config?.allowDownload ?? false;
  const allowPrint = config?.allowPrint ?? false;
  const allowCopy = config?.allowCopy ?? false;

  const toggleFullscreen = () => {
    const elem = document.getElementById('secure-image-container');
    if (!document.fullscreenElement) {
      elem.requestFullscreen().catch(err => {
        console.error(`Error attempting to enable fullscreen: ${err.message}`);
      });
    } else {
      document.exitFullscreen();
    }
  };

  useEffect(() => {
    const handleFullscreenChange = () => {
      setIsFullscreen(!!document.fullscreenElement);
    };
    document.addEventListener('fullscreenchange', handleFullscreenChange);
    return () => document.removeEventListener('fullscreenchange', handleFullscreenChange);
  }, []);

  return (
    <div 
      id="secure-image-container" 
      className={`flex flex-col bg-gray-100 ${isFullscreen ? 'fixed inset-0 z-50' : 'w-full h-[600px] border border-gray-200 rounded-[2px]'}`}
      style={{ userSelect: allowCopy ? 'auto' : 'none' }}
      onContextMenu={(e) => {
        if (!allowCopy && !allowDownload) e.preventDefault();
      }}
    >
      {/* Top Control Bar */}
      <div className="bg-[#1e293b] text-white px-3 py-2 flex flex-wrap items-center justify-between shrink-0 gap-y-2 gap-x-2">
        <div className="flex flex-wrap items-center gap-2">
          
          <div className="flex items-center bg-slate-800 rounded px-2">
            <button onClick={() => setScale(s => Math.max(0.5, s - 0.25))} className="p-1 hover:text-[#2563EB] transition-colors">
              <ZoomOut className="w-4 h-4" />
            </button>
            <span className="text-[13px] font-medium mx-2 min-w-[50px] text-center">
              {Math.round(scale * 100)}%
            </span>
            <button onClick={() => setScale(s => Math.min(4.0, s + 0.25))} className="p-1 hover:text-[#2563EB] transition-colors">
              <ZoomIn className="w-4 h-4" />
            </button>
          </div>
          
          <div className="w-px h-5 bg-slate-700"></div>

          <button onClick={() => setRotation(r => (r + 90) % 360)} className="p-1.5 hover:bg-slate-800 rounded transition-colors" title="Rotate">
            <RotateCw className="w-4 h-4" />
          </button>
        </div>

        <div className="flex items-center gap-2">
          {allowPrint && (
            <button onClick={onPrint} className="p-1.5 hover:bg-slate-800 rounded transition-colors" title="Print">
              <Printer className="w-4 h-4" />
            </button>
          )}
          {allowDownload && (
            <button onClick={onDownload} className="p-1.5 hover:bg-slate-800 rounded transition-colors" title="Download">
              <Download className="w-4 h-4" />
            </button>
          )}
          <button onClick={toggleFullscreen} className="p-1.5 hover:bg-slate-800 rounded transition-colors" title="Full Screen">
            <Maximize className="w-4 h-4" />
          </button>
          
          <div className="w-px h-5 bg-slate-700 hidden sm:block mx-1"></div>
          
          <button onClick={onClose} className="p-1.5 hover:bg-slate-800 rounded transition-colors text-slate-300 hover:text-white flex items-center" title="Close">
            <span className="text-[13px] font-bold">✕ <span className="hidden sm:inline">Close</span></span>
          </button>
        </div>
      </div>

      {/* Image Canvas Area */}
      <div className="flex-1 overflow-auto flex justify-center items-center bg-[#f2f3f3] p-4 relative shadow-inner">
        <div 
          className="transition-transform duration-200"
          style={{ 
            transform: `scale(${scale}) rotate(${rotation}deg)`,
            transformOrigin: 'center center'
          }}
        >
          <img
            src={url}
            alt={meta?.originalName}
            className="max-w-full max-h-[800px] object-contain shadow-[0_4px_12px_rgba(0,0,0,0.1)] bg-white"
            style={allowCopy ? {} : { userSelect: 'none', WebkitUserDrag: 'none' }}
          />
        </div>

        {/* Dynamic Watermark Overlay */}
        <div className="absolute inset-0 pointer-events-none flex items-center justify-center overflow-hidden opacity-[0.06]" style={{ mixBlendMode: 'multiply' }}>
          <div className="transform -rotate-45 text-center text-slate-800" style={{ fontSize: `40px`, fontWeight: 900 }}>
            <div className="tracking-widest uppercase">CONFIDENTIAL</div>
            {meta?.recipientEmail && <div className="text-xl mt-2 font-mono">{meta.recipientEmail}</div>}
            <div className="text-lg mt-1">{new Date().toLocaleDateString()}</div>
          </div>
        </div>
      </div>

      {/* Bottom Status Bar */}
      <div className="bg-white border-t border-[#eaeded] px-3 py-2 flex flex-wrap justify-between items-center shrink-0 gap-y-2 gap-x-4">
        <span className="text-[12px] font-bold text-[#16191f] flex items-center gap-1.5 shrink-0">
          <svg className="w-3.5 h-3.5 text-[#2563EB]" fill="currentColor" viewBox="0 0 20 20"><path fillRule="evenodd" d="M5 9V7a5 5 0 0110 0v2a2 2 0 012 2v5a2 2 0 01-2 2H5a2 2 0 01-2-2v-5a2 2 0 012-2zm8-2v2H7V7a3 3 0 016 0z" clipRule="evenodd"></path></svg>
          Protected by Auroqi
        </span>
        <span className="text-[11.5px] font-medium text-[#545b64] flex flex-wrap gap-2 sm:gap-3 shrink-0 items-center justify-center">
          <span className={allowDownload ? 'text-emerald-600' : ''}>{allowDownload ? 'Download allowed' : 'Download disabled'}</span>
          <span className="text-[#aab7b8]">&bull;</span>
          <span className={allowPrint ? 'text-emerald-600' : ''}>{allowPrint ? 'Print allowed' : 'Print disabled'}</span>
          <span className="text-[#aab7b8]">&bull;</span>
          <span className={allowCopy ? 'text-emerald-600' : ''}>{allowCopy ? 'Copy allowed' : 'Copy disabled'}</span>
        </span>
      </div>
    </div>
  );
}
