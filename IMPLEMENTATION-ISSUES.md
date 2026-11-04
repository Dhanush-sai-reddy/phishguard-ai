# Screenshot scanner implementation issues

Review by Codex, 3 November 2026. Findings are from inspecting the current working tree; they have not been runtime-tested.

## Status: all three findings resolved

The original review was written against the working tree before the fixes below landed. Each finding was re-checked against the current code and confirmed fixed at runtime.

### Reproducing the checks

The runtime verification is committed so it can be rerun rather than taken on trust:

```bash
npm install
npm run dev                 # terminal 1
npm run test:screenshot     # terminal 2
```

`npm run test:screenshot` drives a headless Chromium against the dev server and asserts all three findings plus the URL/Message paste-and-scan regressions. Point it at a different port with `PHISHGUARD_URL=http://localhost:5174 npm run test:screenshot`. The script lives at `tests/screenshot-check.mjs`.

Last run: **ALL CHECKS PASSED** (9 assertions, 0 uncaught page errors).

### 1. QR links can be analyzed twice — RESOLVED

`handleScanExtracted` now normalizes each URL (strips scheme, `www.`, path, query, fragment) and tracks it in a `seenUrls` set. The QR payload is only analyzed as a URL when its normalized form is not already present in the extracted-link list, so a QR URL that also appears in the OCR text produces one set of flags rather than two.

Relevant code: `main.js`, `handleScanExtracted` — `seenUrls` set and the guarded QR block.

Runtime check: the QR demo yields 1 detected link and 2 URL-sourced flags (previously 4).

### 2. Per-flag source attribution is not shown in the results UI — RESOLVED

`renderFlagCards` now renders a `flag-source` badge when a flag carries a `sourceLabel`. Screenshot flags are labelled either `Message text` or `URL: <url>`; URL and message scans are unaffected because their flags carry no `sourceLabel`.

Relevant code: `main.js`, `renderFlagCards`; styles in `style.css` under `.flag-source` / `.source-message` / `.source-url`.

Runtime check: 4/4 flags on the QR demo carry a visible source badge.

### 3. Screenshot tab does not move the tab indicator — RESOLVED

`updateTabIndicator` now selects `elements.tabScreenshot` when `state.currentTab` is `screenshot`, instead of falling back to the Message tab.

Relevant code: `main.js`, `updateTabIndicator`.

Runtime check: indicator moves from `translateX(0px)` (URL) to `translateX(555px)` (Screenshot), matching the Screenshot button's measured offset.

## Notes, not confirmed defects

- The QR payload textarea is intentionally marked `readonly`; users can edit the extracted QR URL in the detected-links list when that URL was extracted into the list.
- Screenshot OCR, QR decoding, and screenshot scoring run in the browser. The browser still downloads Tesseract's worker/language assets on first use. The app may also make its separate existing `/api/health` request at startup when configured with a backend.
- The screenshot path uses the existing deterministic `analyzeMessageDemo` and `analyzeUrlDemo` heuristics. Scores are not validated detection probabilities and there is no live URL reputation lookup in this path.
