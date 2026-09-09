import React, { useRef, useState } from 'react';
import {
  AlertOctagon,
  AlertTriangle,
  Archive,
  CheckCircle2,
  Copy,
  FileCode,
  FileText,
  FileWarning,
  HardDrive,
  Hash,
  Lock,
  Paperclip,
  Shield,
  ShieldAlert,
  UploadCloud,
} from 'lucide-react';
import { AnalyzedAttachment, AttachmentAnalysisResult } from '../types';
import { analyzeSingleAttachment } from '../utils/attachmentAnalyzer';

interface AttachmentAnalysisViewProps {
  attachmentAnalysis: AttachmentAnalysisResult;
  onAddAttachment?: (attachment: AnalyzedAttachment) => void;
}

export const AttachmentAnalysisView: React.FC<AttachmentAnalysisViewProps> = ({
  attachmentAnalysis,
  onAddAttachment,
}) => {
  const [copiedSha, setCopiedSha] = useState<string | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const { attachments, totalAttachments, dangerousCount, reviewCount, safeCount } = attachmentAnalysis;

  const handleCopySha = (sha: string) => {
    navigator.clipboard.writeText(sha);
    setCopiedSha(sha);
    setTimeout(() => setCopiedSha(null), 2000);
  };

  const handleFilesSelected = async (fileList: FileList | null) => {
    if (!fileList || !onAddAttachment) return;

    for (let i = 0; i < fileList.length; i++) {
      const file = fileList[i];
      const buffer = await file.arrayBuffer();
      const analyzed = await analyzeSingleAttachment({
        filename: file.name,
        filesize: file.size,
        contentType: file.type || 'application/octet-stream',
        dataBuffer: buffer,
        index: attachments.length + i,
      });
      onAddAttachment(analyzed);
    }
  };

  const getRiskBadge = (riskLevel: AnalyzedAttachment['riskLevel'], score: number) => {
    if (riskLevel === 'dangerous') {
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-bold bg-rose-500/20 text-rose-300 border border-rose-500/40 uppercase">
          <AlertOctagon className="w-3.5 h-3.5" /> DANGEROUS ({score}/100)
        </span>
      );
    }
    if (riskLevel === 'review') {
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-bold bg-amber-500/20 text-amber-300 border border-amber-500/40 uppercase">
          <AlertTriangle className="w-3.5 h-3.5" /> REVIEW NEEDED ({score}/100)
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 uppercase">
        <CheckCircle2 className="w-3.5 h-3.5" /> SAFE ({score}/100)
      </span>
    );
  };

  const getFileIcon = (att: AnalyzedAttachment) => {
    if (att.isDangerousExtension) return <FileWarning className="w-5 h-5 text-rose-400" />;
    if (att.isMacroEnabledDoc) return <FileCode className="w-5 h-5 text-amber-400" />;
    if (att.isArchive) return <Archive className="w-5 h-5 text-indigo-400" />;
    if (['iso', 'img', 'vhd'].includes(att.primaryExtension)) return <HardDrive className="w-5 h-5 text-rose-400" />;
    return <FileText className="w-5 h-5 text-slate-400" />;
  };

  const formatFileSize = (bytes?: number): string => {
    if (!bytes || bytes <= 0) return '0 B';
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  };

  return (
    <div className="space-y-6" id="attachment-analysis-module">
      {/* Metric Bar */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
          <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Total Attachments</div>
          <div className="text-2xl font-bold text-white mt-1">{totalAttachments}</div>
          <div className="text-[11px] text-slate-500 mt-1">From MIME structure & uploads</div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
          <div className="text-xs font-semibold text-rose-400 uppercase tracking-wider">Dangerous Payloads</div>
          <div className="text-2xl font-bold text-rose-400 mt-1">{dangerousCount}</div>
          <div className="text-[11px] text-slate-500 mt-1">Executables, double-ext, MotW</div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
          <div className="text-xs font-semibold text-amber-400 uppercase tracking-wider">Review Needed</div>
          <div className="text-2xl font-bold text-amber-400 mt-1">{reviewCount}</div>
          <div className="text-[11px] text-slate-500 mt-1">Macro docs, encrypted archives</div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
          <div className="text-xs font-semibold text-emerald-400 uppercase tracking-wider">Clean / Safe</div>
          <div className="text-2xl font-bold text-emerald-400 mt-1">{safeCount}</div>
          <div className="text-[11px] text-slate-500 mt-1">Standard benign formats</div>
        </div>
      </div>

      {/* Ad-hoc Attachment Upload Sandbox */}
      {onAddAttachment && (
        <div
          onDragOver={(e) => {
            e.preventDefault();
            setIsDragging(true);
          }}
          onDragLeave={() => setIsDragging(false)}
          onDrop={(e) => {
            e.preventDefault();
            setIsDragging(false);
            handleFilesSelected(e.dataTransfer.files);
          }}
          onClick={() => fileInputRef.current?.click()}
          className={`p-5 rounded-xl border-2 border-dashed transition-all cursor-pointer text-center ${
            isDragging
              ? 'border-indigo-500 bg-indigo-500/10'
              : 'border-slate-800 hover:border-slate-700 bg-slate-900/50'
          }`}
        >
          <input
            type="file"
            multiple
            ref={fileInputRef}
            onChange={(e) => handleFilesSelected(e.target.files)}
            className="hidden"
          />
          <UploadCloud className="w-8 h-8 text-indigo-400 mx-auto mb-2" />
          <div className="text-xs font-semibold text-white">
            Upload Suspicious File to Test Heuristics (.zip, .exe, .docm, .pdf, etc.)
          </div>
          <p className="text-[11px] text-slate-400 mt-1">
            Drag & drop files here or click to browse. Files are analyzed locally in your browser with zero external transmission.
          </p>
        </div>
      )}

      {/* Attachment List */}
      {attachments.length === 0 ? (
        <div className="p-12 text-center bg-slate-900 border border-slate-800 rounded-xl">
          <Paperclip className="w-8 h-8 text-slate-600 mx-auto mb-2" />
          <p className="text-sm text-slate-400 font-medium">No attachments detected in this email.</p>
          <p className="text-xs text-slate-500 mt-1">
            Upload an attachment above or test sample 3 to inspect malicious payload heuristics.
          </p>
        </div>
      ) : (
        <div className="space-y-4">
          {attachments.map((att) => {
            const isDangerous = att.riskLevel === 'dangerous';
            const isReview = att.riskLevel === 'review';

            return (
              <div
                key={att.id}
                className={`rounded-xl border p-5 transition-all ${
                  isDangerous
                    ? 'bg-slate-900/90 border-rose-800/50'
                    : isReview
                    ? 'bg-slate-900/80 border-amber-800/40'
                    : 'bg-slate-900/60 border-slate-800'
                }`}
              >
                {/* Header: Icon, Name, Size, Risk Badge */}
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-800/80">
                  <div className="flex items-center gap-3">
                    <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800">
                      {getFileIcon(att)}
                    </div>
                    <div>
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-mono text-sm font-bold text-white break-all">{att.filename}</span>
                        {att.isDoubleExtension && (
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-600 text-white uppercase">
                            DOUBLE EXTENSION
                          </span>
                        )}
                        {att.isMacroEnabledDoc && (
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-600 text-white uppercase">
                            VBA MACROS
                          </span>
                        )}
                        {att.isPasswordProtectedArchive && (
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-indigo-600 text-white uppercase flex items-center gap-1">
                            <Lock className="w-3 h-3" /> ENCRYPTED
                          </span>
                        )}
                      </div>
                      <div className="text-xs text-slate-400 mt-0.5 flex items-center gap-3">
                        <span>Size: {formatFileSize(att.filesize)}</span>
                        {att.contentType && (
                          <span>
                            Declared MIME: <span className="font-mono text-slate-300">{att.contentType}</span>
                          </span>
                        )}
                      </div>
                    </div>
                  </div>

                  <div className="self-start sm:self-auto">{getRiskBadge(att.riskLevel, att.riskScore)}</div>
                </div>

                {/* Metadata details: SHA-256 and Indicators */}
                <div className="mt-4 space-y-3 text-xs">
                  {/* SHA-256 */}
                  {att.sha256 && (
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 p-2.5 rounded-lg bg-slate-950 border border-slate-800/80">
                      <div className="flex items-center gap-2 text-slate-400">
                        <Hash className="w-3.5 h-3.5 text-indigo-400" />
                        <span className="font-semibold text-slate-300">SHA-256 Hash:</span>
                        <span className="font-mono text-slate-200 select-all truncate">{att.sha256}</span>
                      </div>
                      <button
                        onClick={() => handleCopySha(att.sha256!)}
                        className="self-start sm:self-auto px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 flex items-center gap-1 text-[11px] transition-colors"
                      >
                        <Copy className="w-3 h-3" />
                        {copiedSha === att.sha256 ? 'Copied!' : 'Copy SHA-256'}
                      </button>
                    </div>
                  )}

                  {/* Archive Nested Files Explorer */}
                  {att.archiveEntries && att.archiveEntries.length > 0 && (
                    <div className="p-3 rounded-lg bg-slate-950/80 border border-slate-800">
                      <div className="text-[11px] font-semibold text-indigo-400 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                        <Archive className="w-3.5 h-3.5" /> Nested Archive Contents ({att.archiveEntries.length} items)
                      </div>
                      <div className="space-y-1.5 font-mono text-[11px] max-h-40 overflow-y-auto">
                        {att.archiveEntries.map((entry, eIdx) => (
                          <div
                            key={eIdx}
                            className={`p-1.5 rounded flex items-center justify-between border ${
                              entry.isDangerous
                                ? 'bg-rose-950/30 border-rose-800/40 text-rose-300 font-bold'
                                : 'bg-slate-900 border-slate-800 text-slate-300'
                            }`}
                          >
                            <span className="truncate">{entry.name}</span>
                            <div className="flex items-center gap-2 shrink-0">
                              <span className="text-slate-500">{formatFileSize(entry.size)}</span>
                              {entry.isDangerous && (
                                <span className="px-1.5 py-0.2 rounded bg-rose-600 text-white text-[10px]">
                                  EXECUTABLE
                                </span>
                              )}
                              {entry.isEncrypted && (
                                <span className="px-1.5 py-0.2 rounded bg-amber-600 text-white text-[10px]">
                                  ENCRYPTED
                                </span>
                              )}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Red flags for this attachment */}
                  {att.flags.length > 0 && (
                    <div className="space-y-1.5">
                      {att.flags.map((flag) => (
                        <div
                          key={flag.id}
                          className={`p-2.5 rounded-lg text-xs flex items-center gap-2 border ${
                            flag.severity === 'critical'
                              ? 'bg-rose-950/30 text-rose-200 border-rose-900/40'
                              : 'bg-amber-950/20 text-amber-200 border-amber-900/30'
                          }`}
                        >
                          <span
                            className={`w-2 h-2 rounded-full shrink-0 ${
                              flag.severity === 'critical' ? 'bg-rose-500' : 'bg-amber-500'
                            }`}
                          />
                          <div>
                            <span className="font-bold">{flag.title}: </span>
                            <span className="text-slate-300">{flag.description}</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
