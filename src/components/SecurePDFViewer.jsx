import React, { useState, useEffect } from 'react';
import { Document, Page, pdfjs } from 'react-pdf';
import { ZoomIn, ZoomOut, Maximize, RotateCw, Search, ChevronLeft, ChevronRight, Download, Printer } from 'lucide-react';
import 'react-pdf/dist/Page/AnnotationLayer.css';
import 'react-pdf/dist/Page/TextLayer.css';
import pdfWorker from 'pdfjs-dist/build/pdf.worker.min.mjs?url';

// Set up the worker for pdf.js (Inlined for offline HTML support)
pdfjs.GlobalWorkerOptions.workerSrc = pdfWorker;

export default function SecurePDFViewer({ url, meta, config, onDownload, onPrint, onClose }) {
  const [numPages, setNumPages] = useState(null);
  const [pageNumber, setPageNumber] = useState(1);
  const [scale, setScale] = useState(1.0);
  const [rotation, setRotation] = useState(0);
  const [isFullscreen, setIsFullscreen] = useState(false);

  const allowDownload = config?.allowDownload ?? false;
  const allowPrint = config?.allowPrint ?? false;
  const allowCopy = config?.allowCopy ?? false;

  const onDocumentLoadSuccess = ({ numPages }) => {
    setNumPages(numPages);
    setPageNumber(1);
  };

  const changePage = (offset) => {
    setPageNumber(prevPageNumber => {
      const newPage = prevPageNumber + offset;
      if (newPage >= 1 && newPage <= numPages) return newPage;
      return prevPageNumber;
    });
  };

  const toggleFullscreen = () => {
    const elem = document.getElementById('secure-pdf-container');
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
      id="secure-pdf-container" 
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
            <button onClick={() => changePage(-1)} disabled={pageNumber <= 1} className="p-1 hover:text-[#2563EB] disabled:opacity-50 transition-colors">
              <ChevronLeft className="w-5 h-5" />
            </button>
            <span className="text-[13px] font-medium mx-2 min-w-[60px] text-center">
              {pageNumber} / {numPages || '-'}
            </span>
            <button onClick={() => changePage(1)} disabled={pageNumber >= numPages} className="p-1 hover:text-[#2563EB] disabled:opacity-50 transition-colors">
              <ChevronRight className="w-5 h-5" />
            </button>
          </div>

          <div className="w-px h-5 bg-slate-700"></div>

          <div className="flex items-center bg-slate-800 rounded px-2">
            <button onClick={() => setScale(s => Math.max(0.5, s - 0.25))} className="p-1 hover:text-[#2563EB] transition-colors">
              <ZoomOut className="w-4 h-4" />
            </button>
            <span className="text-[13px] font-medium mx-2 min-w-[50px] text-center">
              {Math.round(scale * 100)}%
            </span>
            <button onClick={() => setScale(s => Math.min(3.0, s + 0.25))} className="p-1 hover:text-[#2563EB] transition-colors">
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

      {/* PDF Canvas Area */}
      <div className="flex-1 overflow-auto flex justify-center bg-[#f2f3f3] p-4 relative shadow-inner" id="pdf-scroll-container">
        <Document
          file={url}
          onLoadSuccess={onDocumentLoadSuccess}
          loading={
            <div className="flex flex-col items-center justify-center h-full text-[#545b64]">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-[#2563EB] mb-3"></div>
              <p className="text-[13px] font-medium">Loading document...</p>
            </div>
          }
          error={
            <div className="text-[#d13212] p-4 bg-[#fdf3f1] border border-[#d13212] rounded-[2px] text-[13px] font-medium">
              Failed to load PDF.
            </div>
          }
        >
          <Page 
            pageNumber={pageNumber} 
            scale={scale} 
            rotate={rotation}
            renderTextLayer={allowCopy}
            renderAnnotationLayer={false}
            className="shadow-[0_4px_12px_rgba(0,0,0,0.1)] bg-white max-w-full [&>canvas]:!max-w-full [&>canvas]:!h-auto"
          />
        </Document>

        <div className="absolute inset-0 pointer-events-none flex items-center justify-center overflow-hidden opacity-[0.06]" style={{ mixBlendMode: 'multiply' }}>
          <div className="transform -rotate-45 text-center text-slate-800" style={{ fontSize: `${40 * scale}px`, fontWeight: 900 }}>
            <div className="tracking-widest uppercase">{config?.customWatermark || 'CONFIDENTIAL'}</div>
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
