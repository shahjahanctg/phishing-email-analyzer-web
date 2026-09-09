/**
 * Utility functions to parse raw RFC 5322 and multipart MIME emails
 */

export interface ParsedMimeEmail {
  rawHeaders: string;
  subject?: string;
  from?: string;
  to?: string;
  returnPath?: string;
  date?: string;
  bodyText: string;
  bodyHtml?: string;
  attachments: {
    filename: string;
    contentType?: string;
    contentDisposition?: string;
    filesize?: number;
    dataBuffer?: ArrayBuffer;
    isInline?: boolean;
  }[];
}

/**
 * Decode Quoted-Printable encoding
 */
export function decodeQuotedPrintable(str: string): string {
  if (!str) return '';
  // 1. Remove soft line breaks (=\r\n or =\n)
  let result = str.replace(/=\r?\n/g, '');
  // 2. Replace =XX hex bytes
  result = result.replace(/=([0-9A-Fa-f]{2})/g, (_, hex) => {
    try {
      const code = parseInt(hex, 16);
      return String.fromCharCode(code);
    } catch {
      return _;
    }
  });
  return result;
}

/**
 * Decode Base64 string to Uint8Array/ArrayBuffer safely
 */
export function decodeBase64ToBuffer(base64Str: string): ArrayBuffer {
  try {
    const cleanBase64 = base64Str.replace(/\s+/g, '');
    const binaryStr = atob(cleanBase64);
    const len = binaryStr.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      bytes[i] = binaryStr.charCodeAt(i);
    }
    return bytes.buffer;
  } catch {
    return new ArrayBuffer(0);
  }
}

/**
 * Decode Base64 string to UTF-8 text safely
 */
export function decodeBase64ToText(base64Str: string): string {
  try {
    const cleanBase64 = base64Str.replace(/\s+/g, '');
    const binaryStr = atob(cleanBase64);
    const bytes = new Uint8Array(binaryStr.length);
    for (let i = 0; i < binaryStr.length; i++) {
      bytes[i] = binaryStr.charCodeAt(i);
    }
    return new TextDecoder('utf-8').decode(bytes);
  } catch {
    return base64Str;
  }
}

/**
 * Parses raw RFC 5322 string into headers and parts
 */
export function parseRawEmail(rawInput: string): ParsedMimeEmail {
  const normalized = rawInput.replace(/\r\n/g, '\n').replace(/\r/g, '\n');

  // Split headers and body at the first double newline
  const doubleNewlineIndex = normalized.search(/\n\n/);

  let rawHeaders = '';
  let rawBody = '';

  if (doubleNewlineIndex !== -1) {
    rawHeaders = normalized.slice(0, doubleNewlineIndex);
    rawBody = normalized.slice(doubleNewlineIndex + 2);
  } else {
    // If no double newline, treat all as headers if it looks like headers, or all as body
    if (normalized.includes(':') && /^(from|received|to|subject):/im.test(normalized)) {
      rawHeaders = normalized;
      rawBody = '';
    } else {
      rawHeaders = '';
      rawBody = normalized;
    }
  }

  // Extract quick top-level header fields
  const getHeader = (name: string): string | undefined => {
    const regex = new RegExp(`^${name}:\\s*(.*?)(?=\\n\\S|$)`, 'ims');
    const match = rawHeaders.match(regex);
    if (match) {
      return match[1].replace(/\n[ \t]+/g, ' ').trim();
    }
    return undefined;
  };

  const subject = getHeader('Subject');
  const from = getHeader('From');
  const to = getHeader('To');
  const returnPath = getHeader('Return-Path');
  const date = getHeader('Date');
  const contentType = getHeader('Content-Type') || '';

  // Check for multipart boundary
  const boundaryMatch = contentType.match(/boundary=["']?([^"';]+)["']?/i);

  const attachments: ParsedMimeEmail['attachments'] = [];
  let bodyText = '';
  let bodyHtml: string | undefined;

  if (boundaryMatch) {
    const boundary = boundaryMatch[1];
    const parts = rawBody.split(new RegExp(`--${boundary}(?:--)?`));

    for (const part of parts) {
      const trimmedPart = part.trim();
      if (!trimmedPart || trimmedPart === '--') continue;

      const partSplitIdx = trimmedPart.search(/\n\n/);
      let partHeadersStr = '';
      let partBody = '';

      if (partSplitIdx !== -1) {
        partHeadersStr = trimmedPart.slice(0, partSplitIdx);
        partBody = trimmedPart.slice(partSplitIdx + 2);
      } else {
        partBody = trimmedPart;
      }

      const getPartHeader = (name: string): string | undefined => {
        const regex = new RegExp(`^${name}:\\s*(.*?)(?=\\n\\S|$)`, 'ims');
        const match = partHeadersStr.match(regex);
        return match ? match[1].replace(/\n[ \t]+/g, ' ').trim() : undefined;
      };

      const partContentType = getPartHeader('Content-Type') || '';
      const partDisposition = getPartHeader('Content-Disposition') || '';
      const partTransferEncoding = (getPartHeader('Content-Transfer-Encoding') || '').toLowerCase();

      // Check if attachment
      const filenameMatch =
        partDisposition.match(/filename=["']?([^"';]+)["']?/i) ||
        partContentType.match(/name=["']?([^"';]+)["']?/i);

      if (filenameMatch || partDisposition.toLowerCase().includes('attachment')) {
        const filename = filenameMatch ? filenameMatch[1] : `attachment-${attachments.length + 1}`;
        let dataBuffer: ArrayBuffer | undefined;
        let filesize = partBody.length;

        if (partTransferEncoding.includes('base64')) {
          dataBuffer = decodeBase64ToBuffer(partBody);
          filesize = dataBuffer.byteLength;
        }

        attachments.push({
          filename,
          contentType: partContentType.split(';')[0].trim(),
          contentDisposition: partDisposition,
          filesize,
          dataBuffer,
          isInline: partDisposition.toLowerCase().includes('inline'),
        });
      } else if (partContentType.includes('text/html')) {
        let decodedHtml = partBody;
        if (partTransferEncoding.includes('base64')) {
          decodedHtml = decodeBase64ToText(partBody);
        } else if (partTransferEncoding.includes('quoted-printable')) {
          decodedHtml = decodeQuotedPrintable(partBody);
        }
        bodyHtml = decodedHtml;
      } else if (partContentType.includes('text/plain') || !bodyText) {
        let decodedText = partBody;
        if (partTransferEncoding.includes('base64')) {
          decodedText = decodeBase64ToText(partBody);
        } else if (partTransferEncoding.includes('quoted-printable')) {
          decodedText = decodeQuotedPrintable(partBody);
        }
        if (!bodyText) {
          bodyText = decodedText;
        } else {
          bodyText += '\n\n' + decodedText;
        }
      }
    }
  } else {
    // Non-multipart simple email
    const transferEncoding = (getHeader('Content-Transfer-Encoding') || '').toLowerCase();
    let decoded = rawBody;
    if (transferEncoding.includes('base64')) {
      decoded = decodeBase64ToText(rawBody);
    } else if (transferEncoding.includes('quoted-printable')) {
      decoded = decodeQuotedPrintable(rawBody);
    }

    if (contentType.includes('text/html')) {
      bodyHtml = decoded;
      // Strip basic tags for text fallback
      bodyText = decoded.replace(/<[^>]+>/g, ' ');
    } else {
      bodyText = decoded;
    }
  }

  return {
    rawHeaders,
    subject,
    from,
    to,
    returnPath,
    date,
    bodyText: bodyText.trim(),
    bodyHtml,
    attachments,
  };
}
