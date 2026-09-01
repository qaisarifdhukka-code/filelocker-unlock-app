import React, { useRef, useState, useEffect } from 'react';
import { X, Maximize, Play, Pause, Volume2, VolumeX, ShieldAlert, Lock } from 'lucide-react';

export function SecureMediaViewer({ blobUrl, type, fileName, config, email, onClose }) {
  const containerRef = useRef(null);
  const mediaRef = useRef(null);
  const [isFullscreen, setIsFullscreen] = useState(false);
  
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
      className={`flex flex-col bg-black text-white ${isFullscreen ? 'w-full h-screen fixed inset-0 z-50' : 'w-full h-[600px] rounded-lg overflow-hidden border border-gray-800'}`}
    >
      {/* Top Bar */}
      <div className="flex items-center justify-between px-4 py-2 bg-[#0F1629] border-b border-gray-800 shrink-0">
        <div className="flex items-center gap-2">
          <ShieldAlert className="w-5 h-5 text-emerald-500" />
          <span className="text-sm font-medium">{fileName}</span>
        </div>
        <div className="flex items-center gap-3">
          <button 
            onClick={toggleFullscreen}
            className="p-1.5 hover:bg-white/10 rounded transition-colors text-gray-300 hover:text-white"
            title="Fullscreen"
          >
            <Maximize className="w-4 h-4" />
          </button>
          {onClose && (
            <button 
              onClick={onClose}
              className="p-1.5 hover:bg-white/10 rounded transition-colors text-gray-300 hover:text-white ml-2"
              title="Close"
            >
              <X className="w-5 h-5" />
            </button>
          )}
        </div>
      </div>

      {/* Media Area */}
      <div className="flex-1 relative bg-black flex items-center justify-center overflow-hidden group">
        {type === 'video' ? (
          <video
            ref={mediaRef}
            src={blobUrl}
            controls
            controlsList="nodownload noplaybackrate"
            disablePictureInPicture
            className="max-w-full max-h-full w-auto h-auto outline-none"
            onContextMenu={(e) => e.preventDefault()}
          />
        ) : (
          <div className="flex flex-col items-center justify-center w-full h-full">
            <div className="w-32 h-32 mb-8 rounded-full bg-gray-900 flex items-center justify-center border-4 border-gray-800">
              <span className="text-5xl">🎵</span>
            </div>
            <audio
              ref={mediaRef}
              src={blobUrl}
              controls
              controlsList="nodownload noplaybackrate"
              className="w-full max-w-md"
              onContextMenu={(e) => e.preventDefault()}
            />
          </div>
        )}

        {/* Dynamic Watermark Overlay (Only visible when DRM prevents download) */}
        {!config?.allowDownload && (
          <div className="absolute inset-0 pointer-events-none overflow-hidden z-10 opacity-30 select-none">
            <div className="w-[200%] h-[200%] -translate-x-1/4 -translate-y-1/4 -rotate-45 flex flex-wrap gap-16 justify-center content-center">
              {[...Array(50)].map((_, i) => (
                <div key={i} className="text-white text-lg font-bold tracking-widest whitespace-pre-line text-center opacity-40">
                  {watermarkText}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Bottom Status Bar */}
      <div className="bg-[#0F1629] border-t border-gray-800 px-4 py-2 shrink-0 flex justify-between items-center text-xs text-gray-400 font-mono">
        <div className="flex items-center gap-4">
          <span className="flex items-center gap-1.5"><Lock className="w-3 h-3 text-emerald-500" /> AES-256</span>
          <span className="flex items-center gap-1.5">
            {config?.allowDownload ? (
              <span className="text-emerald-500">Download Allowed</span>
            ) : (
              <span className="text-amber-500">Download Restricted</span>
            )}
          </span>
        </div>
      </div>
    </div>
  );
}
