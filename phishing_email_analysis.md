# PHISHING EMAIL ANALYSIS REPORT

**Task:** Task 2 – Analyze a Phishing Email  
**Prepared by:** Dinesh  
**Date:** 2025-12-09

---

## 1. Introduction
This report analyzes a suspicious email that impersonates PayPal. The goal is to detect phishing indicators such as spoofed sender, mismatched URLs, urgent language, suspicious attachments, grammar errors, and (if available) header discrepancies.

---

## 2. Sample Email Used

**Subject:** Your Account Will Be Locked – Verify Now!  
**From:** support@paypa1-security.com

Dear User,

We detected suspicious activity in your PayPal account.  
For your security, your account will be suspended in the next 24 hours.

Please verify your identity immediately by clicking the link below:  
https://paypal-security-check.com/verify

Failure to do so will result in permanent account closure.

Regards,  
PayPal Security Team

**Attachment:** Security_Update.zip

---

## 3. Analysis

### 3.1 Sender Email Spoofing
- Sender: `support@paypa1-security.com` uses **1** instead of **l** → look‑alike domain.
- Does not match the official PayPal domain (`paypal.com`).  
**Indicator:** Strong spoofing signal.

### 3.2 Header Analysis
*(This sample email is synthetic; real headers are not available.)*  
If headers were available, we would verify:
- **SPF**: Does the sending IP have authorization for the domain?
- **DKIM**: Is the message signed by the legitimate domain and does the signature validate?
- **DMARC**: Does alignment pass?  
**Expected phishing outcome:** SPF/DKIM/DMARC likely **fail**; sending IP not part of PayPal infrastructure.

### 3.3 Suspicious Links
Actual URL: `https://paypal-security-check.com/verify`  
- Domain is not owned by PayPal; security‑themed look‑alike.  
**Indicator:** Malicious credential‑harvesting link.

### 3.4 Suspicious Attachment
Attachment: `Security_Update.zip`  
- Financial services rarely send ZIPs; archives often carry malware.  
**Indicator:** High‑risk attachment.

### 3.5 Urgency / Threatening Language
- “Your account will be suspended in the next 24 hours,” “verify immediately,” “permanent closure.”  
**Indicator:** Social engineering using fear and urgency.

### 3.6 Mismatched URLs (Hover Test)
- Link text suggests PayPal verification, but hover reveals `paypal-security-check.com` (not `paypal.com`).  
**Indicator:** Mismatched URL.

### 3.7 Grammar / Spelling Issues
- Generic greeting (“Dear User”), awkward phrasing.  
**Indicator:** Poor professionalism typical of phishing.

---

## 4. Summary of Phishing Indicators
1. Spoofed sender domain (look‑alike)  
2. Non‑PayPal verification link  
3. Urgent / threatening language  
4. Suspicious ZIP attachment  
5. Generic greeting / grammar issues  
6. Mismatched hover URL  
7. Brand impersonation  
8. (If available) Header authentication failures (SPF/DKIM/DMARC)

---

## 5. Conclusion
The email is a phishing attempt designed to steal credentials and potentially deliver malware. It should be reported and blocked; do not interact with links or attachments.

---

## 6. Recommended Actions
- Hover to verify URLs; never click unknown links
- Verify sender domains carefully
- Avoid opening unsolicited attachments
- Report suspicious emails to the security team/provider
- Enforce SPF/DKIM/DMARC on mail gateways
