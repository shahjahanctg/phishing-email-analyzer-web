import JSZip from 'jszip';
import {
  AnalyzedAttachment,
  ArchiveEntryInfo,
  AttachmentAnalysisResult,
  RiskFlag,
} from '../types';

// Dangerous file extensions directly executable in Windows/macOS/Linux
const DANGEROUS_EXTENSIONS = new Set([
  'exe', 'scr', 'bat', 'cmd', 'ps1', 'psm1', 'vbs', 'vbe', 'js', 'jse',
  'wsf', 'wsh', 'hta', 'cpl', 'msc', 'jar', 'pif', 'com', 'gadget',
  'iso', 'img', 'vhd', 'vhdx', 'dll', 'msi', 'msp', 'reg', 'sh', 'bash',
]);

// Office formats that can natively execute VBA macros
const MACRO_OFFICE_EXTENSIONS = new Set([
  'docm', 'dotm', 'xlsm', 'xltm', 'xlam', 'pptm', 'potm', 'ppam', 'ppsm', 'sldm',
]);

// Legacy Office formats that can hold binary macros without clear extension warning
const LEGACY_OFFICE_EXTENSIONS = new Set([
  'doc', 'dot', 'xls', 'xlt', 'xla', 'ppt', 'pot', 'pps',
]);

// Common archive extensions
const ARCHIVE_EXTENSIONS = new Set([
  'zip', 'rar', '7z', 'tar', 'gz', 'bz2', 'xz', 'cab', 'tgz',
]);

// Benign extensions that phishing lures frequently impersonate in double extensions
const BENIGN_MIMICKED_EXTENSIONS = new Set([
  'pdf', 'docx', 'xlsx', 'pptx', 'txt', 'csv', 'jpg', 'jpeg', 'png', 'mp4',
]);

/**
 * Computes SHA-256 hash of a Blob or Uint8Array using Web Crypto API
 */
export async function computeSha256(data: ArrayBuffer | Uint8Array): Promise<string> {
  try {
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
  } catch {
    return 'unavailable';
  }
}

/**
 * Helper to compute SHA-256 from string (for sample or simulated attachments)
 */
export async function computeSha256FromString(text: string): Promise<string> {
  const encoder = new TextEncoder();
  return computeSha256(encoder.encode(text));
}

/**
 * Checks for right-to-left override character (\u202E) used to invert displayed extensions
 * e.g., "invoice\u202Ecod.exe" renders as "invoiceexe.doc"
 */
function hasRightToLeftOverride(filename: string): boolean {
  return /[\u202E\u202D\u202C\u202B\u202A]/.test(filename);
}

/**
 * Parses extensions: detects single or double extension
 */
function extractExtensions(filename: string): {
  primaryExt: string;
  secondaryExt?: string;
  isDoubleExtension: boolean;
} {
  const cleanName = filename.trim().toLowerCase();
  const parts = cleanName.split('.');

  if (parts.length <= 1) {
    return { primaryExt: '', isDoubleExtension: false };
  }

  const primaryExt = parts[parts.length - 1];
  let secondaryExt: string | undefined;
  let isDoubleExtension = false;

  if (parts.length >= 3) {
    const candidateSecondary = parts[parts.length - 2];
    // Check if secondary is a fake benign file extension (e.g. .pdf.exe or .docx.vbs)
    if (BENIGN_MIMICKED_EXTENSIONS.has(candidateSecondary)) {
      secondaryExt = candidateSecondary;
      isDoubleExtension = true;
    }
  }

  return { primaryExt, secondaryExt, isDoubleExtension };
}

/**
 * Inspects a ZIP archive using JSZip to find embedded executables or encrypted entries
 */
export async function inspectZipArchive(data: ArrayBuffer | Uint8Array): Promise<{
  entries: ArchiveEntryInfo[];
  containsDangerous: boolean;
  isEncrypted: boolean;
}> {
  const entries: ArchiveEntryInfo[] = [];
  let containsDangerous = false;
  let isEncrypted = false;

  try {
    const zip = await JSZip.loadAsync(data);
    for (const [relativePath, zipEntry] of Object.entries(zip.files)) {
      if (zipEntry.dir) continue;

      const ext = relativePath.split('.').pop()?.toLowerCase() || '';
      const isDangerous = DANGEROUS_EXTENSIONS.has(ext) || MACRO_OFFICE_EXTENSIONS.has(ext);
      // JSZip can flag encrypted entries via bit flag or internal header
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const entryEncrypted = Boolean((zipEntry as any)._data?.isEncrypted);

      if (isDangerous) containsDangerous = true;
      if (entryEncrypted) isEncrypted = true;

      // Extract uncompressed size if available
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const size = (zipEntry as any)._data?.uncompressedSize || 0;

      entries.push({
        name: relativePath,
        size,
        isDangerous,
        isEncrypted: entryEncrypted,
        comment: zipEntry.comment || undefined,
      });
    }
  } catch {
    // If password-protected or corrupt, JSZip may throw
    isEncrypted = true;
  }

  return { entries, containsDangerous, isEncrypted };
}

/**
 * Analyzes an individual attachment
 */
export async function analyzeSingleAttachment(params: {
  filename: string;
  filesize?: number;
  contentType?: string;
  contentDisposition?: string;
  dataBuffer?: ArrayBuffer;
  index?: number;
}): Promise<AnalyzedAttachment> {
  const { filename, filesize, contentType, contentDisposition, dataBuffer, index = 0 } = params;

  const flags: RiskFlag[] = [];
  const detectedIndicators: string[] = [];
  let riskScore = 0;

  const hasRlo = hasRightToLeftOverride(filename);
  const { primaryExt, secondaryExt, isDoubleExtension } = extractExtensions(filename);

  // SHA-256 Hash
  let sha256: string | undefined;
  if (dataBuffer) {
    sha256 = await computeSha256(dataBuffer);
  } else {
    // Fallback deterministic pseudo-hash based on filename and size for mockup / parsed items
    sha256 = await computeSha256FromString(`${filename}-${filesize || 0}-${contentType || ''}`);
  }

  // 1. RIGHT-TO-LEFT OVERRIDE (RLO) EVASION ATTACK
  if (hasRlo) {
    riskScore += 50;
    detectedIndicators.push('Unicode RLO Spoofing (\\u202E)');
    flags.push({
      id: `att-rlo-${index}`,
      category: 'attachment',
      severity: 'critical',
      title: 'Right-To-Left Override Character Detected (RLO)',
      description: 'The filename contains hidden Unicode directional controls used to flip file extension appearance in the Windows shell (e.g. disguise .exe as .doc).',
      evidence: filename,
      recommendation: 'Block and quarantine immediately.',
    });
  }

  // 2. DOUBLE EXTENSION DECEPTION (.pdf.exe, .docx.vbs, etc.)
  if (isDoubleExtension) {
    riskScore += 45;
    detectedIndicators.push(`Double Extension (.${secondaryExt}.${primaryExt})`);
    flags.push({
      id: `att-double-ext-${index}`,
      category: 'attachment',
      severity: 'critical',
      title: `Double Extension Deception (.${secondaryExt}.${primaryExt})`,
      description: `Attachment mimics a harmless file type (.${secondaryExt}) while executing as a dangerous format (.${primaryExt}) when opened by victims.`,
      evidence: filename,
    });
  }

  // 3. DIRECT DANGEROUS EXECUTABLE EXTENSION
  const isDangerousExtension = DANGEROUS_EXTENSIONS.has(primaryExt);
  if (isDangerousExtension) {
    riskScore += 45;
    detectedIndicators.push(`Dangerous Executable File Type (.${primaryExt})`);
    flags.push({
      id: `att-dangerous-ext-${index}`,
      category: 'attachment',
      severity: 'critical',
      title: `High-Risk Executable Extension (.${primaryExt})`,
      description: `Directly executable script or binary format (.${primaryExt}). Legitimate business correspondence rarely transmits executable payloads.`,
      evidence: `.${primaryExt}`,
      recommendation: 'Prohibit execution. Inspect in an isolated sandbox.',
    });
  }

  // 4. MACRO-ENABLED OFFICE DOCUMENTS
  const isMacroDoc = MACRO_OFFICE_EXTENSIONS.has(primaryExt);
  const isLegacyDoc = LEGACY_OFFICE_EXTENSIONS.has(primaryExt);

  if (isMacroDoc) {
    riskScore += 35;
    detectedIndicators.push(`Macro-Enabled Office Document (.${primaryExt})`);
    flags.push({
      id: `att-macro-doc-${index}`,
      category: 'attachment',
      severity: 'high',
      title: `Macro-Enabled Document Format (.${primaryExt})`,
      description: `This Office document explicitly supports Visual Basic for Applications (VBA) macros, widely used for initial stage malware droppers (Emotet, Qakbot, AgentTesla).`,
      evidence: `.${primaryExt}`,
      recommendation: 'Block macros by default.',
    });
  } else if (isLegacyDoc) {
    riskScore += 15;
    detectedIndicators.push(`Legacy OLE Office Format (.${primaryExt})`);
    flags.push({
      id: `att-legacy-doc-${index}`,
      category: 'attachment',
      severity: 'medium',
      title: `Legacy Binary Office Document (.${primaryExt})`,
      description: `Old 97-2003 binary Office format (.${primaryExt}) can embed VBA macros without the modern modern .docm extension requirement.`,
    });
  }

  // 5. ARCHIVE FILES & NESTED INSPECTION
  const isArchive = ARCHIVE_EXTENSIONS.has(primaryExt);
  let archiveEntries: ArchiveEntryInfo[] | undefined;
  let isPasswordProtectedArchive = false;

  if (isArchive) {
    detectedIndicators.push(`Compressed Archive (.${primaryExt})`);
    riskScore += 15;

    // Deep inspection if data is available
    if (dataBuffer && (primaryExt === 'zip')) {
      const zipInspection = await inspectZipArchive(dataBuffer);
      archiveEntries = zipInspection.entries;
      isPasswordProtectedArchive = zipInspection.isEncrypted;

      if (zipInspection.containsDangerous) {
        riskScore += 40;
        detectedIndicators.push('Archive Contains Nested Executables / Scripts');
        flags.push({
          id: `att-archive-nested-malware-${index}`,
          category: 'attachment',
          severity: 'critical',
          title: 'Dangerous Payload Inside Archive',
          description: 'Deep archive inspection revealed dangerous executable files or scripts nested within this ZIP file.',
          evidence: zipInspection.entries.filter((e) => e.isDangerous).map((e) => e.name).join(', '),
        });
      }

      if (zipInspection.isEncrypted) {
        riskScore += 25;
        detectedIndicators.push('Password-Protected / Encrypted Archive');
        flags.push({
          id: `att-archive-encrypted-${index}`,
          category: 'attachment',
          severity: 'high',
          title: 'Encrypted / Password-Protected Archive',
          description: 'Archive contents cannot be inspected by email security gateways due to encryption, a common tactic to smuggle payloads.',
        });
      }
    } else {
      // Heuristic for filename indications of password protection (e.g. "pass", "protected", "pass_1234")
      const lowerName = filename.toLowerCase();
      if (lowerName.includes('pass') || lowerName.includes('locked') || lowerName.includes('invoice_pdf')) {
        riskScore += 15;
        flags.push({
          id: `att-archive-suspicious-name-${index}`,
          category: 'attachment',
          severity: 'medium',
          title: 'Suspicious Archive Naming Pattern',
          description: 'Archive name suggests evasion or sensitive password distribution.',
        });
      }
    }
  }

  // 6. CONTENT-TYPE / EXTENSION MISMATCH
  if (contentType) {
    const ctLower = contentType.toLowerCase();
    // If extension says .exe or .zip, but MIME says application/pdf
    if ((isDangerousExtension || isArchive) && ctLower.includes('pdf')) {
      riskScore += 30;
      detectedIndicators.push(`MIME Spoofing: ${contentType} vs .${primaryExt}`);
      flags.push({
        id: `att-mime-mismatch-${index}`,
        category: 'attachment',
        severity: 'high',
        title: 'Content-Type / Extension Mismatch',
        description: `Header declares MIME type '${contentType}', but file extension is '.${primaryExt}'. Attackers use this to evade email filters.`,
        evidence: `MIME: ${contentType} | Ext: .${primaryExt}`,
      });
    }
  }

  // 7. DISK IMAGE FORMAT (.iso, .img, .vhd) - Mark of the Web (MotW) Evasion
  if (['iso', 'img', 'vhd', 'vhdx'].includes(primaryExt)) {
    riskScore += 40;
    detectedIndicators.push('Disk Image Container (MotW Evasion)');
    flags.push({
      id: `att-motw-evasion-${index}`,
      category: 'attachment',
      severity: 'critical',
      title: 'Disk Image Payload (Mark-of-the-Web Evasion)',
      description: 'Disk image files (.iso, .img) are mounted as virtual drives by modern OS without propagating the browser security Mark-of-the-Web zone flags.',
      evidence: `.${primaryExt}`,
    });
  }

  // Clamp score
  riskScore = Math.max(0, Math.min(100, riskScore));

  let riskLevel: AnalyzedAttachment['riskLevel'] = 'safe';
  if (riskScore >= 50) {
    riskLevel = 'dangerous';
  } else if (riskScore >= 20) {
    riskLevel = 'review';
  }

  return {
    id: `att-${index}`,
    filename,
    filesize,
    contentType,
    contentDisposition,
    sha256,
    extension: primaryExt,
    primaryExtension: primaryExt,
    isDoubleExtension,
    isDangerousExtension,
    isMacroEnabledDoc: isMacroDoc,
    isArchive,
    isPasswordProtectedArchive,
    archiveEntries,
    detectedIndicators,
    riskScore,
    riskLevel,
    flags,
  };
}

/**
 * Analyzes a collection of attachments
 */
export async function analyzeAttachments(
  attachments: {
    filename: string;
    filesize?: number;
    contentType?: string;
    contentDisposition?: string;
    dataBuffer?: ArrayBuffer;
  }[]
): Promise<AttachmentAnalysisResult> {
  const analyzed: AnalyzedAttachment[] = [];
  const globalFlags: RiskFlag[] = [];

  for (let i = 0; i < attachments.length; i++) {
    const item = attachments[i];
    const res = await analyzeSingleAttachment({ ...item, index: i });
    analyzed.push(res);
  }

  const totalAttachments = analyzed.length;
  const dangerousCount = analyzed.filter((a) => a.riskLevel === 'dangerous').length;
  const reviewCount = analyzed.filter((a) => a.riskLevel === 'review').length;
  const safeCount = analyzed.filter((a) => a.riskLevel === 'safe').length;

  if (dangerousCount > 0) {
    globalFlags.push({
      id: 'att-summary-dangerous',
      category: 'attachment',
      severity: 'critical',
      title: `${dangerousCount} High-Risk Malicious Attachment(s) Flagged`,
      description: 'Executable droppers, macro-enabled files, or evasive double extensions were detected.',
    });
  } else if (reviewCount > 0) {
    globalFlags.push({
      id: 'att-summary-review',
      category: 'attachment',
      severity: 'medium',
      title: `${reviewCount} Attachment(s) Require Manual Security Review`,
      description: 'Archive formats, legacy documents, or unusual MIME descriptors identified.',
    });
  }

  return {
    attachments: analyzed,
    totalAttachments,
    dangerousCount,
    reviewCount,
    safeCount,
    flags: globalFlags,
  };
}
