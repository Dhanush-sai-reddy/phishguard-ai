# PhishGuard: improvement research and build direction

Prepared by Codex, 4 November 2026. This brief reflects the current checkout, including the screenshot/OCR/QR flow. It is a research-backed proposal; no product code changes are included here.

## Recommendation

Position the next version as **“See what this QR will make your phone do.”** Make the screenshot scanner a type-aware preview for web links, UPI payment intents, app links, Wi-Fi credentials, phone/SMS actions, and plain text. The standout use case is a UPI QR or scam screenshot that claims “refund/reward/receive money”: show the actual decoded payee and amount, then explain that the payload is a payment request/action and the user should verify it in their payment app before approving anything.

This builds on what already exists in `main.js` (local OCR, QR decoding, editable extracted links, and source-labelled heuristic findings). It addresses a clear gap: QR payloads are not all URLs, while the current analyzer only gives URL-specific analysis to extracted links and message analysis to OCR text.

## What current PhishGuard already has

- URL and message scans backed by hand-written deterministic rules in `analyzer.js`.
- Screenshot upload, browser OCR, QR decoding, editable OCR text and extracted links, with per-source findings in `main.js`.
- No actual URL fetch/reputation check in the local analyzer. A low score means no configured rule matched; it is not a verified-safe result.
- The implementation has useful grounding and demo value, but its scores are not calibrated detection probabilities and the rules are not validated on a representative dataset.

One presentation issue to fix early: `getScoreVerdict()` currently returns **“Safe / Verified”** for scores up to 20, while the result panel correctly says that a low local score cannot guarantee safety. Remove “Verified” from that label and use wording such as **“No known warning signs found”** plus a visible “This scan did not check the live destination” note.

## Research findings that change the product decision

### QR images carry more than URLs

Trad and Chehab (2025) describe QR payloads for URLs, Wi-Fi, app/deep links, payments, SMS, contacts, calendars, location and plain text. Their generated-data study reports an AUC of 0.9133 for QR-image structural analysis, but this is an early research result on a constructed dataset, not proof a visual QR classifier will work on real-world payment/scam screenshots. The practical product implication is to decode and safely preview payload types first, rather than treating every QR as a URL or claiming that its visual appearance reveals maliciousness. [Paper (arXiv, 2025)](https://arxiv.org/abs/2505.03451)

A newer multi-format dataset paper, CIC-Trap4Phish (submitted February 2026), evaluates both QR-image CNNs and lexical analysis of decoded URLs. Its dataset is generated, so it is useful as a research lead but not a substitute for testing on real QR photos, screenshots and payment intents. [Paper (arXiv, 2026)](https://arxiv.org/abs/2602.09015)

### QR scams matter, and generic warnings are not enough

An ACM AsiaCCS 2025 study ran phishing simulations across organizations with more than 71,000 emails. Quishing emails were about as effective as conventional link emails at leading recipients to the landing page, and were harder for operational detectors to identify. This supports making the QR the central user journey, not a small extra input tab. [Paper (ACM/arXiv, 2025)](https://arxiv.org/abs/2505.12104)

In a 2025 CHI study with 489 participants, advice tailored to the specific email performed better than generic advice, but inaccurate advice reduced phishing-detection accuracy. The UI should therefore show inspectable facts (“QR payload says payee X, amount ₹Y”; “message says refund”) and abstain when OCR or parsing is uncertain. It should not let an LLM invent a sender, brand, payee identity or certainty. [CHI’25 study](https://vaniea.com/publication/saka2025chi/)

A 2025 WISP study found an explainable nudge improved phishing detection accuracy by 10.1% in its experiment and reduced cognitive load. This is promising support for concise evidence plus a next action, though it is a workshop study and not a guarantee of the same effect for PhishGuard users. [WISP’25 paper](https://aisel.aisnet.org/wisp2025/4)

An SOUPS 2024 interview study of 29 US mobile users found people judging SMS authenticity focused more on message content, format and links than on sender number or short code. PhishGuard should make the suspicious claim and destination/action easy to compare, instead of relying on sender metadata it does not have. [SOUPS’24 study](https://www.usenix.org/conference/soups2024/presentation/tabassum-sarah)

### Payments give PhishGuard a specific, local story

NPCI’s UPI linking specification defines payment intent fields such as payee VPA (`pa`), payee name (`pn`), amount (`am`), currency (`cu`) and note (`tn`). That makes a local parser feasible: render these fields as a preview without launching a UPI app or authorizing a transaction. [NPCI UPI Linking Specification v1.6](https://www.labnol.org/files/linking.pdf)

NPCI’s fraud-awareness guidance says scanning a QR and entering a UPI PIN is for making a payment, not receiving money; the RBI’s public guidance likewise says not to scan a QR to receive money. Use this as a narrowly scoped, cited warning when the message claims a refund, reward or incoming payment but the QR payload is a payment intent. Do not infer fraud from a UPI QR by itself: legitimate merchant QR codes are common. [NPCI fraud awareness](https://www.npci.org.in/fraud-awareness) · [RBI QR safety guidance](https://rbikehtahai.rbi.org.in/qr)

### Evaluation must avoid demo-only confidence

Phish360 provides 10,748 real-world URL/HTML/screenshot triplets from 2020–2023, including realistic legitimate login pages, multiple languages and deduplication intended to reduce leakage. It can help evaluate a future webpage-impersonation component, but it does not cover UPI QR payloads or incoming-message screenshots. Build a small separate, documented QR/UPI evaluation set with benign payment requests and diverse scam claims; split by source/campaign/template rather than randomly splitting near-duplicates. [Phish360 dataset and methodology](https://web.cs.hacettepe.edu.tr/~selman/phish360-dataset/)

## Prioritized improvements

### P0 — Correct the promise

1. Replace “Safe / Verified” with “No known warning signs found” (or an equivalent unambiguous label).
2. Visibly separate **observed evidence** from **interpretation** and **next step**.
3. For OCR or QR decoding failures, say “Could not read this” / “No action decoded”; never silently convert missing evidence into a low-risk conclusion.

This is small, immediately feasible, and prevents the current UI from promising more than the analyzer checks.

### P1 — Build the differentiating UPI/QR preview

1. Classify decoded QR contents locally: `https URL`, `other URL`, `UPI payment intent`, `phone/SMS`, `Wi-Fi`, `app/deep link`, `plain text`, or `unknown`. Parse, do not execute; never auto-open a payload.
2. For `upi://pay`, display payee name, VPA, amount, currency and transaction note when present. Missing fields should be shown as missing, not guessed. Treat names/amounts as unverified values supplied by the code.
3. Add a claim-vs-action comparison for high-confidence phrases in OCR. Example: **Message says “claim your refund”; QR encodes a payment to `name@handle` for ₹500.** Explain the conflict and recommend verifying in the official payment app before approval.
4. Use exact evidence excerpts and source labels: OCR text, decoded QR field, or URL hostname. Keep an “uncertain” state when OCR confidence is weak or the parser cannot identify the intent.
5. Demo a benign shop UPI QR, a payment QR paired with a fake “refund” message, a malicious login URL QR, and a non-URL QR. The benign payment case is important to show the tool does not label every payment QR dangerous.

Feasibility: high for a browser-only prototype. It can reuse jsQR and the current Vite UI; parsing UPI query parameters and rendering a preview requires no inference API, credential, or payment integration. Scope the first build to UPI plus URLs and plain-text payloads if time is tight; classify other schemes as “unsupported action type” rather than attempting unsafe handling.

### P2 — Replace the single opaque score with a compact decision card

Lead with **What this would do → Why to pause → What to do now**. Keep the numeric heuristic score secondary or remove it from the screenshot result. Use separate labels for “known match,” “suspicious structure,” and “not checked.” A heuristic score should not look like a measured probability.

### P3 — Add a small evaluation pack before claiming accuracy

Create a versioned local fixture set of screenshots and QR payloads, each with expected extraction and expected findings. Include:

- legitimate bank/service alerts and merchant UPI codes;
- fake refund/reward and “scan to receive” claims with outgoing payment QR payloads;
- credential phishing URLs, redirects/shorteners as raw strings, QR images with non-URL payloads;
- blurry/low-contrast images, OCR-confusable characters, missing QR, and multilingual examples if those languages are claimed.

Track extraction success, false alarms on benign items, missed suspicious items and abstentions separately. Split by campaign/template/source to reduce leakage. Do not publish a single accuracy number from a handful of hand-picked demo examples.

## Avoid for this iteration

- Do not add a generic “AI phishing score” API call as the central feature: it adds privacy/network questions while weakening explainability.
- Do not build QR visual-pattern ML from a small self-made dataset. Recent papers are promising but report results on constructed datasets; this is too much model/data work for the immediate win.
- Do not integrate PayPal/Tally/payment execution into PhishGuard. The useful payment safety behavior is preview and verification, not moving money.
- Do not call UPI payee details verified identity. They are payload values; only the user's official payment app/bank can present the confirmation flow.

## Suggested hackathon pitch

> **PhishGuard previews what a suspicious screenshot or QR code will make your phone do. It extracts the claim and the hidden action, then shows the evidence before you open a link or approve a payment.**

Demo the mismatch: a message promises a refund, but the QR encodes a payment to a VPA with a fixed amount. Then show a legitimate shop QR as a benign control. The differentiator is the before-action explanation and the narrow UPI scenario, not claiming a novel OCR or ML detector.

## Sources

- Trad & Chehab, “Detecting Quishing Attacks with Machine Learning Techniques Through QR Code Analysis” (2025): https://arxiv.org/abs/2505.03451
- Nejati et al., “CIC-Trap4Phish: A Unified Multi-Format Dataset for Phishing and Quishing Attachment Detection” (2026 preprint): https://arxiv.org/abs/2602.09015
- Weinz et al., “The Impact of Emerging Phishing Threats: Assessing Quishing and LLM-generated Phishing Emails against Organizations” (ACM AsiaCCS 2025): https://arxiv.org/abs/2505.12104
- Saka et al., “Judging Phishing Under Uncertainty: How Do Users Handle Inaccurate Automated Advice?” (CHI 2025): https://vaniea.com/publication/saka2025chi/
- Wagner et al., “Email Phishing Prevention: An Explainable Nudging Approach” (WISP 2025): https://aisel.aisnet.org/wisp2025/4
- Tabassum et al., “What Drives SMiShing Susceptibility?” (SOUPS 2024): https://www.usenix.org/conference/soups2024/presentation/tabassum-sarah
- National Payments Corporation of India, UPI Linking Specification v1.6: https://www.labnol.org/files/linking.pdf
- NPCI Fraud Awareness: https://www.npci.org.in/fraud-awareness
- RBI QR Safety: https://rbikehtahai.rbi.org.in/qr
- Phish360 dataset: https://web.cs.hacettepe.edu.tr/~selman/phish360-dataset/
