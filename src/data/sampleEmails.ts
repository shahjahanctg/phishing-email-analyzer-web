export interface SampleEmailItem {
  id: string;
  name: string;
  category: 'Header Spoof' | 'URL Phishing' | 'Malicious Attachment' | 'Legitimate (Clean)';
  description: string;
  highlightedModule: 'headers' | 'urls' | 'attachments' | 'all';
  rawEmail: string;
}

export const SAMPLE_EMAILS: SampleEmailItem[] = [
  {
    id: 'sample-header-spoof',
    name: 'Sample 1: Executive CEO Fraud / BEC (Pure-Header Spoof)',
    category: 'Header Spoof',
    highlightedModule: 'headers',
    description:
      'Impersonates corporate CEO demanding an urgent confidential wire transfer. Exploits SPF/DMARC failure, mismatched envelope Return-Path, and diverted Reply-To address.',
    rawEmail: `Delivered-To: victim-cfo@acmecorp.com
Received: by 2002:a05:6512:1234 with SMTP id abc123def;
        Wed, 09 Sep 2026 04:12:30 -0700 (PDT)
Received: from mail-relay-bulletproof.top (mail-relay-bulletproof.top [185.220.101.5])
        by mx.google.com with ESMTP id z9si123456plm.42.2026.09.09.04.12.28
        for <victim-cfo@acmecorp.com>;
        Wed, 09 Sep 2026 04:12:28 -0700 (PDT)
Authentication-Results: mx.google.com;
        spf=softfail (google.com: domain of transitioning bounce-relay98@freemail-bulletproof.top does not designate 185.220.101.5 as permitted sender) smtp.mailfrom=bounce-relay98@freemail-bulletproof.top;
        dkim=none;
        dmarc=fail (p=reject dis=none) header.from=acmecorp.com
Received-SPF: softfail (google.com: domain of transitioning bounce-relay98@freemail-bulletproof.top does not designate 185.220.101.5 as permitted sender) client-ip=185.220.101.5;
From: Sarah Jenkins <sarah.jenkins@acmecorp.com>
Return-Path: <bounce-relay98@freemail-bulletproof.top>
Reply-To: Sarah Jenkins (Direct Desk) <exec-sarah-jenkins@desk-relay-urgent.com>
To: victim-cfo@acmecorp.com
Subject: [CONFIDENTIAL & URGENT] Overseas Acquisition Deposit - Wire Details
Date: Wed, 09 Sep 2026 04:11:00 -0700
Message-ID: <raw-spam-bot-887419@anon-server>
X-Originating-IP: [185.220.101.5]
X-Mailer: PHPMailer 5.2.14 (https://github.com/PHPMailer/PHPMailer)
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 8bit

Hi Mark,

I am currently in an all-day executive board briefing with the regulatory committee and cannot take telephone calls.

We are closing the European supplier acquisition this morning before foreign exchange market settlement. Please process a same-day SWIFT wire remittance of $148,500 immediately to the escrow account provided below.

Beneficiary Bank: Cayman Offshore Commerce Bank
Account Number: 8492048194
SWIFT / BIC: CAYMOF22
Reference: ACME-HOLDING-CONFIDENTIAL

Please do not mention this to the accounting floor until press release embargo lifts at 4:00 PM EST. Reply directly to this email as soon as the wire transaction confirmation slip is generated.

Thank you,
Sarah Jenkins
Chief Executive Officer
Acme Corporation`,
  },
  {
    id: 'sample-url-phishing',
    name: 'Sample 2: Microsoft 365 Credential Harvest (URL Spoof & Typosquat)',
    category: 'URL Phishing',
    highlightedModule: 'urls',
    description:
      'Urgent IT security alert warning of password expiration. Features display-text vs href mismatch, typosquatting "micros0ft", excessive subdomain depth, and high-risk .xyz/.live redirect chains.',
    rawEmail: `Received: from mail-dispatch-eu.net (mail-dispatch-eu.net [194.135.25.80])
        by mail.enterprise.com with ESMTP id ghjk987;
        Wed, 09 Sep 2026 03:45:12 +0000
Authentication-Results: mail.enterprise.com;
        spf=pass (mail.enterprise.com: domain of notice@mail-dispatch-eu.net designates 194.135.25.80 as permitted sender) smtp.mailfrom=notice@mail-dispatch-eu.net;
        dkim=fail (bad signature) header.i=@mail-dispatch-eu.net;
        dmarc=fail (p=quarantine) header.from=microsoft.com
From: "Microsoft Security Operations" <account-security-noreply@microsoft.com>
Return-Path: <notice@mail-dispatch-eu.net>
To: employee@enterprise.com
Subject: [ACTION REQUIRED] Your Microsoft 365 Password Expires in 24 Hours
Date: Wed, 09 Sep 2026 03:44:00 +0000
Message-ID: <ms-alert-9918237@microsoft-notice.eu>
MIME-Version: 1.0
Content-Type: text/html; charset=UTF-8
Content-Transfer-Encoding: 8bit

<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: Arial, sans-serif; color: #222; line-height: 1.5;">
  <div style="max-width: 600px; border: 1px solid #ddd; padding: 24px; border-radius: 6px;">
    <div style="font-size: 20px; font-weight: bold; color: #0078d4; margin-bottom: 16px;">
      Microsoft Security Operations
    </div>
    <p>Dear Valued User,</p>
    <p>Your enterprise Microsoft 365 workplace access credentials will expire on <strong>September 10, 2026 at 00:00 UTC</strong>.</p>
    <p>To avoid immediate disruption to your Outlook mail, OneDrive sync, and Teams collaboration services, you must retain your existing password via the official corporate identity portal:</p>
    
    <div style="margin: 24px 0;">
      <a href="https://login.micros0ft-verify-portal.xyz/auth/oauth2?redirect=https%3A%2F%2Faccount-harvest-c2.live%2Ftoken" style="background-color: #0078d4; color: #ffffff; padding: 12px 24px; text-decoration: none; border-radius: 4px; font-weight: bold; display: inline-block;">
        Keep Existing Password
      </a>
    </div>

    <p style="font-size: 13px; color: #666;">
      Direct link verification: <br>
      <a href="https://login.micros0ft-verify-portal.xyz/auth/oauth2?redirect=https%3A%2F%2Faccount-harvest-c2.live%2Ftoken">https://login.microsoftonline.com/common/oauth2/v2.0/authorize</a>
    </p>

    <hr style="border: 0; border-top: 1px solid #eee; margin: 20px 0;">
    <p style="font-size: 11px; color: #999;">
      Microsoft Corporation, One Microsoft Way, Redmond, WA 98052.<br>
      Secondary portal backup: <a href="http://198.51.100.44/webscr/session-expired">http://198.51.100.44/webscr/session-expired</a>
    </p>
  </div>
</body>
</html>`,
  },
  {
    id: 'sample-attachment-malware',
    name: 'Sample 3: Weaponized Invoice Dropper (Dangerous Attachments & Double Extension)',
    category: 'Malicious Attachment',
    highlightedModule: 'attachments',
    description:
      'Disguised overdue payment reminder carrying a double-extension executable (.pdf.exe), a macro-enabled Word document (.docm), and an encrypted archive.',
    rawEmail: `Received: from mail.global-freight-billing.com (mail.global-freight-billing.com [203.0.113.19])
        by mx.corporate-gateway.net with ESMTP id z9823;
        Wed, 09 Sep 2026 01:20:00 +0000
Authentication-Results: mx.corporate-gateway.net;
        spf=pass smtp.mailfrom=billing@global-freight-billing.com;
        dkim=pass (d=global-freight-billing.com);
        dmarc=none
From: "Global Freight Accounts" <billing@global-freight-billing.com>
Return-Path: <billing@global-freight-billing.com>
To: accounts-payable@victimcorp.com
Subject: OVERDUE STATEMENT: Invoice #INV-2026-9921 Attached
Date: Wed, 09 Sep 2026 01:18:00 +0000
Message-ID: <INV-2026-8812739@freight-billing.com>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="----=_Part_98234_7716281.2026"

------=_Part_98234_7716281.2026
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 7bit

Dear Accounts Payable,

Our automated accounting records show that Invoice #INV-2026-9921 for maritime container handling services is now 45 days past due. A late surcharge of $1,250 has been assessed.

Please review the attached formal statement:
1. INVOICE_OCT2026_STATEMENT.pdf.exe (Primary PDF Statement)
2. Remittance_Macro_Guide.docm (Macro Remittance Authorization)
3. Supporting_Vouchers_Encrypted.zip (Password: 2026secure)

Kindly remit funds within 48 business hours to avoid collection dispatch.

Global Logistics Remittance Bureau
Tel: +1-800-555-0199

------=_Part_98234_7716281.2026
Content-Type: application/pdf; name="INVOICE_OCT2026_STATEMENT.pdf.exe"
Content-Disposition: attachment; filename="INVOICE_OCT2026_STATEMENT.pdf.exe"
Content-Transfer-Encoding: base64

TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAsAAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4g
RE9TIG1vZGUuDQ0KJAAAAAAAAABQRQAATAEDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==

------=_Part_98234_7716281.2026
Content-Type: application/vnd.ms-word.document.macroEnabled.12; name="Remittance_Macro_Guide.docm"
Content-Disposition: attachment; filename="Remittance_Macro_Guide.docm"
Content-Transfer-Encoding: base64

UEsDBBQAAAAIAAAAAAAAAAAAAAAAAAAAAAAJAAAAZG9jUHJvcHMvUEsDBBQAAAAIAAAAAAAA
AAAAAAAAAAAAAAALAAAAZW1iZWRkZWREYXRhUEsDBBQAAAAIAAAAAAAAAAAAAAAAAAAAAAAP
AAAAdnJhUHJvamVjdC5iaW5QSwECHwMUAAAACAAAAAAAAAAAAAAAAAAAAAAACQAAAAAAAAAA
AAAAAAAAAAAAZG9jUHJvcHMvUEsBAh8DFAAAAAgAAAAAAAAAAAAAAAAAAAAAAAsAAAAAAAAA
AAAAAAAAAAAAYZW1iZWRkZWREYXRhUEsBAh8DFAAAAAgAAAAAAAAAAAAAAAAAAAAAAA8AAAAA
AAAAAAAAAAAAAAAAAAB2cmFQcm9qZWN0LmJpblBLBQYAAAAAAwADAFYAAAA7AAAAAAA=

------=_Part_98234_7716281.2026
Content-Type: application/zip; name="Supporting_Vouchers_Encrypted.zip"
Content-Disposition: attachment; filename="Supporting_Vouchers_Encrypted.zip"
Content-Transfer-Encoding: base64

UEsDBBQAAAAIAAAAAAAAAAAAAAAAAAAAAAAJAAAAdGVzdC5leGVQSwECHwMUAAAACAAAAAAA
AAAAAAAAAAAAAAAAAAkAAAAAAAAAAAAAAAAAAAAAdGVzdC5leGVQSwUGAAAAAAEAAQA3AAAA
JAAAAAAA

------=_Part_98234_7716281.2026--`,
  },
  {
    id: 'sample-clean-benchmark',
    name: 'Sample 4: Legitimate Benchmark (Clean GitHub Security Notification)',
    category: 'Legitimate (Clean)',
    highlightedModule: 'all',
    description:
      'Authentic transactional notification from GitHub. Full SPF, DKIM (d=github.com), and DMARC alignment pass. All URLs match authentic domains with no deceptive anchors or attachments.',
    rawEmail: `Delivered-To: developer@techcompany.io
Received: by 2002:a17:906:4d0e with SMTP id w14csp12345;
        Wed, 09 Sep 2026 00:15:20 -0700 (PDT)
Received: from out-1.smtp.github.com (out-1.smtp.github.com [192.30.252.192])
        by mx.google.com with ESMTPS id v10si54321plm.12.2026.09.09.00.15.19
        for <developer@techcompany.io>;
        Wed, 09 Sep 2026 00:15:19 -0700 (PDT)
Authentication-Results: mx.google.com;
        spf=pass (google.com: domain of support@github.com designates 192.30.252.192 as permitted sender) smtp.mailfrom=support@github.com;
        dkim=pass header.i=@github.com header.s=pf2014 header.b=V8xK9Z;
        dmarc=pass (p=reject sp=reject dis=none) header.from=github.com
From: "GitHub" <notifications@github.com>
Return-Path: <support@github.com>
To: developer@techcompany.io
Subject: [GitHub] Your personal access token (classic) is due to expire
Date: Wed, 09 Sep 2026 00:15:00 -0700
Message-ID: <github/security-token-notice/9817263@github.com>
MIME-Version: 1.0
Content-Type: text/html; charset=UTF-8

<!DOCTYPE html>
<html>
<body>
  <p>Hi @developer,</p>
  <p>Your personal access token (classic) <strong>DeployKey-Staging</strong> will expire in 7 days on September 16, 2026.</p>
  <p>To ensure your automated CI/CD pipelines continue operating smoothly, you can regenerate this token:</p>
  <p>
    <a href="https://github.com/settings/tokens">https://github.com/settings/tokens</a>
  </p>
  <p>Thanks,<br>The GitHub Team</p>
</body>
</html>`,
  },
];
