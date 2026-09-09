import React, { useRef, useState } from 'react';
import {
  AlertCircle,
  Check,
  FileCode,
  FileSpreadsheet,
  FileText,
  FileUp,
  Mail,
  Sparkles,
  Upload,
  X,
} from 'lucide-react';
import { SAMPLE_EMAILS, SampleEmailItem } from '../data/sampleEmails';
import { ManualTriageFormState } from '../types';

interface EmailInputModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSubmitRaw: (raw: string, mode: 'eml' | 'raw_headers') => void;
  onSubmitManual: (form: ManualTriageFormState) => void;
  onLoadSample: (sample: SampleEmailItem) => void;
}

export const EmailInputModal: React.FC<EmailInputModalProps> = ({
  isOpen,
  onClose,
  onSubmitRaw,
  onSubmitManual,
  onLoadSample,
}) => {
  const [activeTab, setActiveTab] = useState<'upload' | 'paste' | 'manual'>('upload');
  const [pastedText, setPastedText] = useState('');
  const [isDragging, setIsDragging] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Manual triage form state
  const [manualForm, setManualForm] = useState<ManualTriageFormState>({
    from: 'support@brand-verify.xyz',
    returnPath: 'bounce-collector@malicious-relay.top',
    replyTo: 'credential-stealer@freemail.ru',
    subject: 'URGENT: Your Account Has Been Locked',
    date: new Date().toUTCString(),
    spfResult: 'fail',
    dkimResult: 'none',
    dmarcResult: 'fail',
    receivedHopsText:
      'from mail-relay-open.top (185.220.101.5) by mx.google.com with ESMTP;\nfrom 192.168.1.50 by mail-relay-open.top with SMTP;',
    bodyText:
      'Dear Customer,\n\nWe detected unauthorized login attempts from a foreign IP address.\nPlease verify your credentials immediately to avoid permanent account termination.\n\nVerify Account: https://login.micros0ft-security.xyz/auth?redirect=http://c2-exfil.live',
    urlsList: 'https://login.micros0ft-security.xyz/auth?redirect=http://c2-exfil.live',
    attachmentsList: 'Security_Update_Utility.pdf.exe, 48200\nRecovery_Instructions.docm, 12840',
  });

  if (!isOpen) return null;

  const handleFileUpload = (file: File) => {
    const reader = new FileReader();
    reader.onload = (e) => {
      const content = e.target?.result as string;
      if (content) {
        onSubmitRaw(content, 'eml');
        onClose();
      }
    };
    reader.readAsText(file);
  };

  const handleManualSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onSubmitManual(manualForm);
    onClose();
  };

  const handlePasteSubmit = () => {
    if (!pastedText.trim()) return;
    onSubmitRaw(pastedText, 'raw_headers');
    onClose();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm overflow-y-auto">
      <div className="relative w-full max-w-4xl bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl overflow-hidden my-8">
        {/* Modal Header */}
        <div className="p-5 border-b border-slate-800 flex items-center justify-between bg-slate-950/70">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-indigo-500/20 text-indigo-400">
              <Mail className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-bold text-white">Load Email for Triage Analysis</h3>
              <p className="text-xs text-slate-400">
                Upload raw .eml, paste RFC 5322 headers, or input manual structured parameters
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Realistic Preset Sample Selector Banner */}
        <div className="p-4 bg-slate-950/90 border-b border-slate-800">
          <div className="text-[11px] font-bold text-slate-400 uppercase tracking-wider mb-2 flex items-center gap-1.5">
            <Sparkles className="w-3.5 h-3.5 text-amber-400" /> Quick-Load Benchmark Phishing Samples:
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2">
            {SAMPLE_EMAILS.map((sample) => (
              <button
                key={sample.id}
                onClick={() => {
                  onLoadSample(sample);
                  onClose();
                }}
                className="p-2.5 text-left rounded-lg bg-slate-900 hover:bg-indigo-950/40 border border-slate-800 hover:border-indigo-500/50 transition-all text-xs group"
              >
                <div className="font-bold text-slate-200 group-hover:text-indigo-300 truncate">
                  {sample.category}
                </div>
                <div className="text-[11px] text-slate-400 truncate mt-0.5">{sample.name.split(':')[1]}</div>
              </button>
            ))}
          </div>
        </div>

        {/* Input Mode Navigation Tabs */}
        <div className="flex border-b border-slate-800 bg-slate-950/40 text-xs font-semibold">
          <button
            onClick={() => setActiveTab('upload')}
            className={`px-5 py-3 flex items-center gap-2 border-b-2 transition-colors ${
              activeTab === 'upload'
                ? 'border-indigo-500 text-indigo-400 bg-slate-900/60'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <FileUp className="w-4 h-4" /> 1. Upload .EML / .TXT File
          </button>
          <button
            onClick={() => setActiveTab('paste')}
            className={`px-5 py-3 flex items-center gap-2 border-b-2 transition-colors ${
              activeTab === 'paste'
                ? 'border-indigo-500 text-indigo-400 bg-slate-900/60'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <FileCode className="w-4 h-4" /> 2. Paste RFC 5322 Raw Email
          </button>
          <button
            onClick={() => setActiveTab('manual')}
            className={`px-5 py-3 flex items-center gap-2 border-b-2 transition-colors ${
              activeTab === 'manual'
                ? 'border-indigo-500 text-indigo-400 bg-slate-900/60'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <FileSpreadsheet className="w-4 h-4" /> 3. Structured Manual Form
          </button>
        </div>

        {/* Tab 1: Upload File */}
        {activeTab === 'upload' && (
          <div className="p-6">
            <div
              onDragOver={(e) => {
                e.preventDefault();
                setIsDragging(true);
              }}
              onDragLeave={() => setIsDragging(false)}
              onDrop={(e) => {
                e.preventDefault();
                setIsDragging(false);
                if (e.dataTransfer.files?.[0]) {
                  handleFileUpload(e.dataTransfer.files[0]);
                }
              }}
              onClick={() => fileInputRef.current?.click()}
              className={`p-10 rounded-xl border-2 border-dashed text-center cursor-pointer transition-all ${
                isDragging
                  ? 'border-indigo-500 bg-indigo-500/10'
                  : 'border-slate-700 hover:border-indigo-500 bg-slate-950/60'
              }`}
            >
              <input
                type="file"
                ref={fileInputRef}
                accept=".eml,.txt,.msg"
                onChange={(e) => {
                  if (e.target.files?.[0]) {
                    handleFileUpload(e.target.files[0]);
                  }
                }}
                className="hidden"
              />
              <Upload className="w-10 h-10 text-indigo-400 mx-auto mb-3" />
              <div className="text-sm font-bold text-white">Drop raw email (.eml or .txt) here</div>
              <p className="text-xs text-slate-400 mt-1">Or click to select an email file exported from your mail client</p>
              <div className="mt-4 inline-flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-800 text-slate-300 text-xs font-medium">
                Supports RFC 5322, RFC 2045 multipart MIME, and base64 attachments
              </div>
            </div>
          </div>
        )}

        {/* Tab 2: Paste Raw */}
        {activeTab === 'paste' && (
          <div className="p-6 space-y-4">
            <div>
              <label className="text-xs font-semibold text-slate-300 block mb-1.5">
                Paste RFC 5322 Raw Email (Headers + Body):
              </label>
              <textarea
                value={pastedText}
                onChange={(e) => setPastedText(e.target.value)}
                placeholder="From: sender@example.com&#10;Subject: Urgent&#10;Authentication-Results: ...&#10;Received: from ...&#10;&#10;Email body text with https://links.com..."
                className="w-full h-72 p-3.5 rounded-xl bg-slate-950 border border-slate-800 font-mono text-xs text-slate-200 focus:outline-none focus:border-indigo-500 resize-none leading-relaxed"
              />
            </div>
            <div className="flex justify-end gap-3">
              <button
                onClick={onClose}
                className="px-4 py-2 rounded-lg text-xs text-slate-400 hover:text-white"
              >
                Cancel
              </button>
              <button
                onClick={handlePasteSubmit}
                disabled={!pastedText.trim()}
                className="px-5 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-xs font-bold text-white transition-colors"
              >
                Analyze Email
              </button>
            </div>
          </div>
        )}

        {/* Tab 3: Structured Manual Form */}
        {activeTab === 'manual' && (
          <form onSubmit={handleManualSubmit} className="p-6 space-y-4 max-h-[65vh] overflow-y-auto">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
              <div>
                <label className="font-semibold text-slate-400 block mb-1">From Header:</label>
                <input
                  type="text"
                  value={manualForm.from}
                  onChange={(e) => setManualForm({ ...manualForm, from: e.target.value })}
                  className="w-full px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-white font-mono focus:border-indigo-500"
                />
              </div>
              <div>
                <label className="font-semibold text-slate-400 block mb-1">Return-Path (Envelope):</label>
                <input
                  type="text"
                  value={manualForm.returnPath}
                  onChange={(e) => setManualForm({ ...manualForm, returnPath: e.target.value })}
                  className="w-full px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-white font-mono focus:border-indigo-500"
                />
              </div>
              <div>
                <label className="font-semibold text-slate-400 block mb-1">Reply-To Address:</label>
                <input
                  type="text"
                  value={manualForm.replyTo}
                  onChange={(e) => setManualForm({ ...manualForm, replyTo: e.target.value })}
                  className="w-full px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-white font-mono focus:border-indigo-500"
                />
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
              <div>
                <label className="font-semibold text-slate-400 block mb-1">Subject:</label>
                <input
                  type="text"
                  value={manualForm.subject}
                  onChange={(e) => setManualForm({ ...manualForm, subject: e.target.value })}
                  className="w-full px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-white focus:border-indigo-500"
                />
              </div>
              <div>
                <label className="font-semibold text-slate-400 block mb-1">Date:</label>
                <input
                  type="text"
                  value={manualForm.date}
                  onChange={(e) => setManualForm({ ...manualForm, date: e.target.value })}
                  className="w-full px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-white focus:border-indigo-500 font-mono"
                />
              </div>
            </div>

            {/* Authentication Protocols */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs p-3 rounded-xl bg-slate-950 border border-slate-800">
              <div>
                <label className="font-semibold text-slate-400 block mb-1">SPF Result:</label>
                <select
                  value={manualForm.spfResult}
                  onChange={(e) =>
                    setManualForm({
                      ...manualForm,
                      spfResult: e.target.value as ManualTriageFormState['spfResult'],
                    })
                  }
                  className="w-full px-2.5 py-1.5 rounded-lg bg-slate-900 border border-slate-700 text-white font-mono"
                >
                  <option value="pass">PASS</option>
                  <option value="fail">FAIL</option>
                  <option value="softfail">SOFTFAIL</option>
                  <option value="neutral">NEUTRAL</option>
                  <option value="none">NONE</option>
                </select>
              </div>

              <div>
                <label className="font-semibold text-slate-400 block mb-1">DKIM Result:</label>
                <select
                  value={manualForm.dkimResult}
                  onChange={(e) =>
                    setManualForm({
                      ...manualForm,
                      dkimResult: e.target.value as ManualTriageFormState['dkimResult'],
                    })
                  }
                  className="w-full px-2.5 py-1.5 rounded-lg bg-slate-900 border border-slate-700 text-white font-mono"
                >
                  <option value="pass">PASS</option>
                  <option value="fail">FAIL</option>
                  <option value="none">NONE</option>
                </select>
              </div>

              <div>
                <label className="font-semibold text-slate-400 block mb-1">DMARC Result:</label>
                <select
                  value={manualForm.dmarcResult}
                  onChange={(e) =>
                    setManualForm({
                      ...manualForm,
                      dmarcResult: e.target.value as ManualTriageFormState['dmarcResult'],
                    })
                  }
                  className="w-full px-2.5 py-1.5 rounded-lg bg-slate-900 border border-slate-700 text-white font-mono"
                >
                  <option value="pass">PASS</option>
                  <option value="fail">FAIL</option>
                  <option value="none">NONE</option>
                </select>
              </div>
            </div>

            {/* Body text */}
            <div className="text-xs">
              <label className="font-semibold text-slate-400 block mb-1">Email Body Text:</label>
              <textarea
                value={manualForm.bodyText}
                onChange={(e) => setManualForm({ ...manualForm, bodyText: e.target.value })}
                rows={4}
                className="w-full p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-white font-mono focus:border-indigo-500 resize-none"
              />
            </div>

            {/* URLs list & Attachments list */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
              <div>
                <label className="font-semibold text-slate-400 block mb-1">
                  Embedded URLs (one per line):
                </label>
                <textarea
                  value={manualForm.urlsList}
                  onChange={(e) => setManualForm({ ...manualForm, urlsList: e.target.value })}
                  rows={3}
                  className="w-full p-2 rounded-lg bg-slate-950 border border-slate-800 text-white font-mono focus:border-indigo-500 resize-none"
                />
              </div>
              <div>
                <label className="font-semibold text-slate-400 block mb-1">
                  Attachments (filename, size_bytes):
                </label>
                <textarea
                  value={manualForm.attachmentsList}
                  onChange={(e) => setManualForm({ ...manualForm, attachmentsList: e.target.value })}
                  rows={3}
                  className="w-full p-2 rounded-lg bg-slate-950 border border-slate-800 text-white font-mono focus:border-indigo-500 resize-none"
                />
              </div>
            </div>

            <div className="flex justify-end gap-3 pt-2">
              <button
                type="button"
                onClick={onClose}
                className="px-4 py-2 rounded-lg text-xs text-slate-400 hover:text-white"
              >
                Cancel
              </button>
              <button
                type="submit"
                className="px-5 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-xs font-bold text-white transition-colors"
              >
                Run Structured Triage
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
};
