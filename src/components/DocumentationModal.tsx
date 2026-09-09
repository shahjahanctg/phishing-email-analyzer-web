import React from 'react';
import {
  BookOpen,
  Brain,
  CheckCircle2,
  ExternalLink,
  Layers,
  Network,
  Shield,
  X,
  Zap,
} from 'lucide-react';

interface DocumentationModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const DocumentationModal: React.FC<DocumentationModalProps> = ({ isOpen, onClose }) => {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm overflow-y-auto">
      <div className="relative w-full max-w-4xl bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl overflow-hidden my-8">
        {/* Modal Header */}
        <div className="p-5 border-b border-slate-800 flex items-center justify-between bg-slate-950/70">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-indigo-500/20 text-indigo-400">
              <BookOpen className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-bold text-white">Triage Architecture & Detection Heuristics</h3>
              <p className="text-xs text-slate-400">
                Deterministic security rules, privacy safeguards, and future AI/ML enhancement roadmap
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

        {/* Content */}
        <div className="p-6 max-h-[75vh] overflow-y-auto space-y-6 text-xs text-slate-300 leading-relaxed">
          {/* Section 1: Deterministic Engine Philosophy */}
          <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
            <h4 className="text-sm font-bold text-white flex items-center gap-2">
              <Shield className="w-4 h-4 text-indigo-400" /> 1. Deterministic Rule-Based Architecture
            </h4>
            <p>
              This analyzer operates on <strong>100% deterministic, offline-capable heuristics</strong>. No confidential
              internal email headers, employee addresses, or sensitive attachments are transmitted to third-party APIs.
              All parsing, JSZip archive inspections, and SHA-256 cryptographic hashing occur inside the security analyst&apos;s
              browser sandbox.
            </p>
          </div>

          {/* Section 2: Three Core Modules Breakdown */}
          <div className="space-y-3">
            <h4 className="text-sm font-bold text-white flex items-center gap-2">
              <Layers className="w-4 h-4 text-indigo-400" /> 2. Core Detection Modules
            </h4>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800">
                <div className="font-bold text-slate-200 mb-1">Header Analysis (RFC 5322)</div>
                <ul className="list-disc pl-4 space-y-1 text-slate-400 text-[11px]">
                  <li>From vs Return-Path envelope alignment check</li>
                  <li>Reply-To diversion detection (BEC / wire fraud)</li>
                  <li>RFC 7601 SPF, DKIM, and DMARC policy parsing</li>
                  <li>MTA Received hop chain tracing & private IP leakage</li>
                  <li>Forged or anomalous Message-ID structure</li>
                </ul>
              </div>

              <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800">
                <div className="font-bold text-slate-200 mb-1">URL & Link Analysis</div>
                <ul className="list-disc pl-4 space-y-1 text-slate-400 text-[11px]">
                  <li>Visible display text vs destination href mismatches</li>
                  <li>Typosquatting & Levenshtein distance on top brands</li>
                  <li>Punycode IDN homoglyph evasion (xn--)</li>
                  <li>Direct IP hostnames & excessive subdomain depth</li>
                  <li>High-risk abuse TLDs & redirect query parameter tracking</li>
                </ul>
              </div>

              <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800">
                <div className="font-bold text-slate-200 mb-1">Attachment Inspection</div>
                <ul className="list-disc pl-4 space-y-1 text-slate-400 text-[11px]">
                  <li>Dangerous binaries (.exe, .scr, .bat, .vbs, .ps1, .hta)</li>
                  <li>Double extensions (.pdf.exe, .docx.js) & Unicode RLO</li>
                  <li>Macro-enabled Office templates (.docm, .xlsm)</li>
                  <li>Disk images (.iso, .img) evading Mark-of-the-Web</li>
                  <li>In-browser ZIP inspection & SHA-256 hash generation</li>
                </ul>
              </div>
            </div>
          </div>

          {/* Section 3: Machine Learning & Threat Intel Roadmap */}
          <div className="p-4 rounded-xl bg-indigo-950/20 border border-indigo-900/40 space-y-3">
            <h4 className="text-sm font-bold text-indigo-300 flex items-center gap-2">
              <Brain className="w-4 h-4 text-indigo-400" /> 3. Modular Future Roadmap: ML & External Threat Feeds
            </h4>
            <p className="text-slate-300">
              While the MVP strictly uses rule-based heuristics to ensure speed and auditability, the codebase is modularly
              isolated so ML classifiers and external threat intelligence can be plugged in without refactoring core triage:
            </p>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-[11px]">
              <div className="p-2.5 rounded-lg bg-slate-950/80 border border-slate-800">
                <span className="font-bold text-white block mb-1">Natural Language / LLM Tone Analysis:</span>
                Detects urgent social engineering coercion, authority impersonation, and gift-card solicitations in email body text where no links or attachments exist.
              </div>
              <div className="p-2.5 rounded-lg bg-slate-950/80 border border-slate-800">
                <span className="font-bold text-white block mb-1">Threat Intel Hooks (VirusTotal / URLScan):</span>
                Hooks to query file SHA-256 hashes against VirusTotal or submit suspicious URLs to URLScan.io for live DOM rendering and screenshot capture.
              </div>
              <div className="p-2.5 rounded-lg bg-slate-950/80 border border-slate-800">
                <span className="font-bold text-white block mb-1">Live WHOIS & RDAP Protocol:</span>
                Query actual domain registration dates to pinpoint freshly registered domains (&lt; 48 hours old) with mathematical certainty.
              </div>
              <div className="p-2.5 rounded-lg bg-slate-950/80 border border-slate-800">
                <span className="font-bold text-white block mb-1">Bayesian Spam / Ham Classification:</span>
                Statistical token frequency analysis trained on corporate spam corpuses to complement structural header rules.
              </div>
            </div>
          </div>

          {/* Section 4: Edge Case Handling */}
          <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
            <h4 className="text-sm font-bold text-white flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-400" /> 4. Edge-Case Hardening
            </h4>
            <ul className="list-disc pl-4 space-y-1 text-slate-400 text-[11px]">
              <li><strong>Malformed / Missing Headers:</strong> Gracefully defaults to unauthenticated scoring without throwing exceptions.</li>
              <li><strong>Quoted-Printable & Base64 Decoding:</strong> Automatically unfolds soft breaks and hex-escapes in MIME payloads.</li>
              <li><strong>Missing URLs or Attachments:</strong> Renders clean dedicated empty states without breaking triage calculations.</li>
              <li><strong>Massive Received Hop Chains:</strong> Dynamically adjusts timeline layout and flags routing obfuscation over 10 hops.</li>
            </ul>
          </div>
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-slate-800 bg-slate-950 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-xs font-bold text-white transition-colors"
          >
            Close Documentation
          </button>
        </div>
      </div>
    </div>
  );
};
