# PhishGuard: current component research (2026-11-03)

## What exists

`analyzer.js` is a shared deterministic heuristic engine. URL checks are hardcoded brand typos, raw-IP hosts, a fixed TLD list, dot count, credential-like path words, and a short allowlist. Message checks are weighted keyword patterns. The README is explicit that it does not query threat feeds or inspect the destination. The UI already accepts pasted URL/message text and gives explainable flags; it has no image intake/OCR.

## Best SafeSpace demo upgrade: screenshot-to-evidence scan

Add one clear **Scan screenshot** entry point. Process the image locally in the browser: run OCR for visible message text, decode any QR code, extract URLs from both OCR and QR results, then send message text and each URL separately through the existing analyzers. Display the screenshot, extracted text, decoded URL, and which evidence generated each flag. Keep the final action with the user; never auto-open a decoded link. This shows a concrete new input mode while reusing the project's existing explainable engine instead of claiming a new detector.

Why this fits: the FBI warned in 2025 about unsolicited-package QR scams that route victims to credential collection or malicious downloads, and in January 2026 issued a QR-code spearphishing advisory. [IC3 2025 QR-code PSA](https://www.ic3.gov/PSA/2025/PSA250731) · [FBI 2026 QR-code spearphishing advisory](https://www.ic3.gov/CSA/2026/260108.pdf). A browser OCR route is feasible with [Tesseract.js](https://github.com/naptha/tesseract.js), which wraps WebAssembly Tesseract and uses a Web Worker in-browser; its docs note the worker/core/language assets may come from CDNs unless configured locally. [jsQR](https://github.com/cozmo/jsQR) accepts image pixel data and returns QR contents, so it can feed the already-existing URL analyzer.

**Demo contract:** say “extracts text/links and checks for known warning signs,” not “proves this is safe.” Show “couldn't read” / “no link found” as an inconclusive result. Treat OCR output as noisy and let users inspect/correct it. QR decoding only reveals payload; it does not establish whether its destination is malicious.

## Accuracy and novelty pitfalls

- The existing URL score is a heuristic, not a calibrated probability. A low score or no matching pattern must not be presented as a safe verdict. TLD abuse lists and hand-selected brand typos age quickly; URL structure alone cannot establish reputation.
- OCR can confuse characters and punctuation in URLs; dropped dots or `l`/`1` substitutions can change the destination. Preserve the image-derived string and require a human to review/correct it before analysis. Do not fetch it automatically.
- Message keyword matches are context-blind (quoted warnings, benign account notices, multilingual text); they can create false alarms and miss paraphrases. Surface exact matched spans and treat the result as triage.
- A screenshot/QR workflow is a useful product improvement, not novel OCR or phishing research. The credible differentiator is a fast local flow with visible evidence and honest uncertainty.

## Other component options

1. **Unicode lookalike signal (small, offline URL upgrade).** Unicode UTS #39 specifies confusable and mixed-script detection, including Latin/Cyrillic lookalikes, but explicitly cautions that confusability is contextual and its skeleton is an internal comparison form, not display text. Use a maintained UTS #39 confusables dataset/library; don't invent a hand-written Unicode map or reject every internationalized domain. [Unicode UTS #39](https://www.unicode.org/reports/tr39/). This is more defensible than adding more static TLDs, but less compelling as the main demo feature.
2. **Reputation lookup (later, optional).** Google Safe Browsing v5 now documents real-time URL checks and an optional Oblivious HTTP privacy relay. However, lookup introduces network latency/outages and sends a URL check off-device; Google's terms say submitted URLs/associated data may be used to maintain/improve products, and Safe Browsing API use is non-commercial absent a separate agreement. This is a weak fit for an offline-first hackathon demo; keep it opt-in and disclose data flow if pursued. [Safe Browsing overview](https://developers.google.com/safe-browsing/reference) · [No-storage real-time mode](https://developers.google.com/safe-browsing/reference/No.Storage.Real.Time.Mode) · [Terms](https://developers.google.com/safe-browsing/terms?hl=en).

## Cost / runtime / source risks

- **OCR:** no per-scan model/API fee if Tesseract.js runs locally, but the WASM core and language model must be downloaded/cached; cold start, mobile CPU/battery, screenshot size, and weak/blurry text affect responsiveness and recall. Tesseract.js documentation says it does not improve the base recognition model. Keep an upload-size limit, show progress, and make text paste the fallback. [Tesseract.js scope and setup](https://github.com/naptha/tesseract.js/) · [Local asset setup](https://github.com/naptha/tesseract.js/blob/master/docs/local-installation.md).
- **QR:** jsQR is a small local parser over image pixels; difficult, obscured, low-resolution, or non-QR codes may not decode. It only extracts payload; this is not reputation checking. Bundle and pin dependencies/assets for repeatable demo behavior.
- **Reputation service:** creates API-key/terms work, network dependency, user-content disclosure, and possible recurring usage cost (confirm current plan before integrating); a hit means known-list match, while a miss is not proof of safety. Safe Browsing API has non-commercial restrictions. Don't put a server secret in a static frontend.
- **External assets:** if OCR workers/language files load from a CDN, offline-after-first-load behavior depends on network/cache and the remote host. Bundle/pin them or clearly label first-load requirements.

## Recommendation

For this SafeSpace demo, build screenshot-to-evidence scanning with local OCR + QR decode, then reuse the existing message and URL heuristics. It is feasible in the current Vite/browser architecture, costs no per-image inference fee, creates a visible before/after demo, and addresses an input gap already named in the README. Keep reputation lookup and broad model/LLM claims out of the critical path. If there is spare time, add UTS #39-based mixed-script/confusable warnings as a focused offline URL signal.
