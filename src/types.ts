export type RiskSeverity = 'clean' | 'low' | 'suspicious' | 'high' | 'critical';

export interface RiskFlag {
  id: string;
  category: 'header' | 'url' | 'attachment' | 'general';
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  title: string;
  description: string;
  evidence?: string;
  recommendation?: string;
}

export interface AuthProtocolResult {
  status: 'pass' | 'fail' | 'softfail' | 'neutral' | 'none' | 'temperror' | 'permerror';
  domain?: string;
  details?: string;
  rawHeader?: string;
}

export interface ReceivedHop {
  index: number;
  fromHost?: string;
  fromIp?: string;
  byHost?: string;
  protocol?: string;
  timestamp?: string;
  delaySec?: number;
  isPrivateIp?: boolean;
  isSuspiciousRelay?: boolean;
  raw: string;
}

export interface ParsedHeaders {
  from?: { name?: string; address: string; domain: string };
  to?: string[];
  replyTo?: { name?: string; address: string; domain: string };
  returnPath?: { address: string; domain: string };
  subject?: string;
  date?: string;
  messageId?: string;
  xOriginatingIp?: string;
  xMailer?: string;
  spf: AuthProtocolResult;
  dkim: AuthProtocolResult;
  dmarc: AuthProtocolResult;
  receivedChain: ReceivedHop[];
  rawHeaders: Record<string, string[]>;
  rawText: string;
}

export interface HeaderAnalysisResult {
  headers: ParsedHeaders;
  trustScore: number; // 0 (malicious) to 100 (trusted)
  trustLevel: 'High Trust' | 'Moderate Trust' | 'Suspicious' | 'Dangerous / Forged';
  flags: RiskFlag[];
  scoreBreakdown: {
    factor: string;
    impact: number;
    description: string;
  }[];
}

export interface RedirectHop {
  url: string;
  status?: number;
  reason?: string;
}

export interface TyposquatMatch {
  matchedBrand: string;
  targetDomain: string;
  similarity: number; // 0 to 1
  technique: 'levenshtein' | 'homoglyph' | 'combosquatting' | 'subdomain_spoof';
}

export interface AnalyzedUrl {
  id: string;
  originalUrl: string;
  normalizedUrl: string;
  displayText?: string;
  isDisplayMismatch: boolean;
  mismatchReason?: string;
  protocol: string;
  hostname: string;
  domain: string;
  subdomain: string;
  subdomainDepth: number;
  tld: string;
  path: string;
  searchParams: Record<string, string>;
  isIpAddress: boolean;
  isPunycode: boolean;
  punycodeDecoded?: string;
  isShortener: boolean;
  simulatedRedirectChain: RedirectHop[];
  finalDestination: string;
  typosquatMatch?: TyposquatMatch;
  isHighRiskTld: boolean;
  hasPhishingKeywords: boolean;
  flaggedKeywords: string[];
  estimatedDomainAgeCategory: 'fresh / suspicious (< 30 days)' | 'medium age (< 1 year)' | 'established (> 1 year)' | 'unknown / dynamic';
  riskScore: number; // 0 (safe) to 100 (critical)
  riskLevel: 'safe' | 'suspicious' | 'high-risk';
  flags: RiskFlag[];
}

export interface UrlAnalysisResult {
  urls: AnalyzedUrl[];
  totalUrls: number;
  highRiskCount: number;
  suspiciousCount: number;
  safeCount: number;
  hasDisplayMismatch: boolean;
  flags: RiskFlag[];
}

export interface ArchiveEntryInfo {
  name: string;
  size: number;
  isDangerous: boolean;
  isEncrypted: boolean;
  comment?: string;
}

export interface AnalyzedAttachment {
  id: string;
  filename: string;
  filesize?: number;
  contentType?: string;
  contentDisposition?: string;
  sha256?: string;
  extension: string;
  primaryExtension: string;
  isDoubleExtension: boolean;
  isDangerousExtension: boolean;
  isMacroEnabledDoc: boolean;
  isArchive: boolean;
  isPasswordProtectedArchive?: boolean;
  archiveEntries?: ArchiveEntryInfo[];
  detectedIndicators: string[];
  riskScore: number; // 0 (safe) to 100 (critical)
  riskLevel: 'safe' | 'review' | 'dangerous';
  flags: RiskFlag[];
  contentDataUrl?: string;
}

export interface AttachmentAnalysisResult {
  attachments: AnalyzedAttachment[];
  totalAttachments: number;
  dangerousCount: number;
  reviewCount: number;
  safeCount: number;
  flags: RiskFlag[];
}

export interface TriageReport {
  timestamp: string;
  analyzedEmailSubject?: string;
  overallScore: number; // 0 (Safe) to 100 (Definite Phishing)
  phishingLikelihood: 'Critical Risk' | 'High Risk' | 'Moderate Risk' | 'Low Risk' | 'Safe / Clean';
  confidence: 'High' | 'Medium' | 'Low';
  verdictSummary: string;
  keyRedFlags: string[];
  headerAnalysis: HeaderAnalysisResult;
  urlAnalysis: UrlAnalysisResult;
  attachmentAnalysis: AttachmentAnalysisResult;
  emailBodyText?: string;
  emailBodyHtml?: string;
  rawInput: string;
  inputMode: 'eml' | 'raw_headers' | 'manual';
}

export interface ManualTriageFormState {
  from: string;
  returnPath: string;
  replyTo: string;
  subject: string;
  date: string;
  spfResult: 'pass' | 'fail' | 'softfail' | 'neutral' | 'none';
  dkimResult: 'pass' | 'fail' | 'none';
  dmarcResult: 'pass' | 'fail' | 'none';
  receivedHopsText: string;
  bodyText: string;
  urlsList: string;
  attachmentsList: string;
}
