import React, { useRef, useState, useEffect } from 'react';
import { X, Maximize, Lock, ShieldAlert, FileVideo, Music } from 'lucide-react';

export function SecureMediaViewer({ blobUrl, type, fileName, config, email, onClose }) {
  const containerRef = useRef(null);
  const mediaRef = useRef(null);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [isPlaying, setIsPlaying] = useState(false);
  
  // Watermark variables
  const now = new Date();
  const dateStr = now.toLocaleDateString() + ' ' + now.toLocaleTimeString();
  const watermarkTitle = config?.customWatermark ? config.customWatermark : 'CONFIDENTIAL';
  const watermarkText = email ? `${watermarkTitle} - ${email}\n${dateStr}` : `${watermarkTitle}\n${dateStr}`;

  useEffect(() => {
    const handleFullscreenChange = () => {
      setIsFullscreen(!!document.fullscreenElement);
    };
    document.addEventListener('fullscreenchange', handleFullscreenChange);
    return () => document.removeEventListener('fullscreenchange', handleFullscreenChange);
  }, []);

  const toggleFullscreen = () => {
    if (!document.fullscreenElement) {
      containerRef.current?.requestFullscreen().catch(err => {
        console.error(`Error attempting to enable fullscreen: ${err.message}`);
      });
    } else {
      document.exitFullscreen();
    }
  };

  return (
    <div 
      ref={containerRef}
      className={`flex flex-col bg-[#050505] text-white font-sans ${
        isFullscreen 
          ? 'w-full h-screen fixed inset-0 z-[9999]' 
          : 'w-full h-[650px] rounded-xl overflow-hidden border border-[#222] shadow-2xl ring-1 ring-white/10'
      }`}
    >
      {/* Top Bar - Glassmorphism */}
      <div className="flex items-center justify-between px-5 py-3 bg-[#0a0a0a]/80 backdrop-blur-md border-b border-white/5 shrink-0 z-20">
        <div className="flex items-center gap-3">
          <div className="p-1.5 bg-emerald-500/10 rounded-md">
            {type === 'video' ? (
              <FileVideo className="w-4 h-4 text-emerald-400" />
            ) : (
              <Music className="w-4 h-4 text-emerald-400" />
            )}
          </div>
          <span className="text-sm font-semibold tracking-wide text-gray-200 truncate max-w-[300px]">
            {fileName}
          </span>
        </div>
        <div className="flex items-center gap-2">
          <button 
            onClick={toggleFullscreen}
            className="p-2 bg-white/5 hover:bg-white/15 rounded-lg transition-all duration-200 text-gray-400 hover:text-white flex items-center gap-2 text-xs font-semibold uppercase tracking-wider"
            title="Fullscreen"
          >
            <Maximize className="w-4 h-4" />
            <span className="hidden sm:inline">{isFullscreen ? 'Exit Fullscreen' : 'Fullscreen'}</span>
          </button>
          {onClose && (
            <button 
              onClick={onClose}
              className="p-2 bg-red-500/10 hover:bg-red-500/20 rounded-lg transition-all duration-200 text-red-400 hover:text-red-300 ml-1"
              title="Close Viewer"
            >
              <X className="w-5 h-5" />
            </button>
          )}
        </div>
      </div>

      {/* Media Area */}
      <div className="flex-1 relative bg-black flex items-center justify-center overflow-hidden group">
        
        {/* Subtle background glow for audio */}
        {type === 'audio' && (
          <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
            <div className="w-[400px] h-[400px] bg-emerald-500/10 rounded-full blur-[100px]"></div>
          </div>
        )}

        {type === 'video' ? (
          <video
            ref={mediaRef}
            src={blobUrl}
            controls
            controlsList="nodownload noplaybackrate nofullscreen"
            disablePictureInPicture
            onPlay={() => setIsPlaying(true)}
            onPause={() => setIsPlaying(false)}
            className="w-full h-full object-contain outline-none z-10"
            onContextMenu={(e) => e.preventDefault()}
          />
        ) : (
          <div className="flex flex-col items-center justify-center w-full h-full z-10 relative">
            <div className="relative group cursor-default">
              <div className="absolute inset-0 bg-emerald-400 blur-xl opacity-20 group-hover:opacity-30 transition-opacity rounded-full"></div>
              <div className="w-40 h-40 mb-10 rounded-full bg-[#111] flex items-center justify-center border border-white/10 shadow-2xl relative z-10">
                <Music className="w-16 h-16 text-emerald-400 opacity-80" />
              </div>
            </div>
            <audio
              ref={mediaRef}
              src={blobUrl}
              controls
              controlsList="nodownload noplaybackrate"
              onPlay={() => setIsPlaying(true)}
              onPause={() => setIsPlaying(false)}
              className="w-full max-w-md [&::-webkit-media-controls-panel]:bg-[#111] [&::-webkit-media-controls-panel]:border [&::-webkit-media-controls-panel]:border-white/10 [&::-webkit-media-controls-panel]:shadow-xl"
              onContextMenu={(e) => e.preventDefault()}
            />
          </div>
        )}

        {/* Dynamic Watermark Overlay (Only visible when DRM prevents download) */}
        {!config?.allowDownload && (
          <div className="absolute inset-0 pointer-events-none overflow-hidden z-[50] select-none mix-blend-overlay opacity-50">
            <div className="w-[200%] h-[200%] -translate-x-1/4 -translate-y-1/4 -rotate-[30deg] flex flex-wrap gap-x-24 gap-y-20 justify-center content-center">
              {[...Array(40)].map((_, i) => (
                <div key={i} className="text-white text-xl md:text-2xl font-bold tracking-widest whitespace-pre-line text-center opacity-30 shadow-black drop-shadow-md">
                  {watermarkText}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Bottom Status Bar - Sleek minimal design */}
      <div className="bg-[#0a0a0a] border-t border-white/5 px-5 py-2.5 shrink-0 flex justify-between items-center text-[11px] text-gray-500 font-mono tracking-widest uppercase z-20">
        <div className="flex items-center gap-6">
          <span className="flex items-center gap-2">
            <ShieldAlert className="w-3.5 h-3.5 text-emerald-500/70" /> 
            <span>Military Grade Encryption</span>
          </span>
          <span className="flex items-center gap-2">
            <Lock className="w-3.5 h-3.5 text-emerald-500/70" /> 
            <span>AES-256</span>
          </span>
        </div>
        <div className="flex items-center gap-2">
          {config?.allowDownload ? (
            <span className="text-emerald-400/80 bg-emerald-400/10 px-2 py-0.5 rounded">Download Allowed</span>
          ) : (
            <span className="text-amber-400/80 bg-amber-400/10 px-2 py-0.5 rounded">Download Restricted</span>
          )}
        </div>
      </div>
    </div>
  );
}
