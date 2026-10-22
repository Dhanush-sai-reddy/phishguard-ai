# Submission copy — PhishGuard AI

Reusable answers for NextSpark Hacks 2026 and SafeSpace Hacks 2026.

## Title

PhishGuard AI — Don't click. Verify.

## Tagline

Paste any suspicious link or message. Get a threat score, the exact red flags, and what to do next — in under a second.

## Problem

Phishing is still the most common way accounts get taken over, and the people most exposed are the least equipped to judge a link: students, older relatives, small teams without security staff. Existing tools either block silently ("this site is unsafe") or dump a wall of technical indicators. Neither teaches the person why the link is dangerous, so the same mistake repeats next week.

## Solution

PhishGuard AI is a two-field safety check. The user pastes a URL or a message; the app returns a 0–100 threat score, a plain-language verdict, the specific signals that fired, and three concrete actions. Every flag explains the mechanism — for example, "paypa1" substitutes the digit 1 for the letter l to imitate paypal.com — so the result is a short lesson, not just a block.

## Features

- URL analysis: typosquatting, raw-IP hosts, high-abuse TLDs, excessive subdomains, credential-harvesting paths
- Message analysis: urgency pressure, fake windfalls, credential requests, authority impersonation, spam formatting
- Consistent five-band verdict with an animated gauge
- Explainable flag cards with severity and reasoning
- Actionable safety guidance tailored to the verdict
- Local, clearable scan history (browser only)
- Works offline in demo mode; optional GPT layer for nuanced cases
- Rate-limited API, no accounts, no stored scans

## How it works

1. The frontend normalizes input and posts `{ type, content }` to `/api/analyze`.
2. The backend runs deterministic signal checks, takes the strongest matched signal as the score, and maps it to a verdict band.
3. The heuristic engine is a single shared module (`analyzer.js`) used by both the server and the static build, so the same input gets the same score everywhere. If an API key is configured, the input goes to an LLM with a strict JSON schema; any failure falls back to that same module.
4. The UI renders the score, flags, summary, and tips, and stores the result locally.

Deterministic scoring matters: the same input always gets the same score, so a judge can retry a demo and see the same verdict.

## Built with

`vite` `javascript` `css` `node.js` `express` `openai` `html5`

## Challenges

- Keeping demo mode useful with no API key, while never pretending heuristics are a trained model
- Making the verdict bands consistent between the server, the local fallback, and the gauge
- Designing a result screen that is readable in three seconds without hiding the reasoning

## What we learned

Explainability is the product. A score alone changes nothing; a sentence like "the domain swaps l for 1" is what makes someone check the address bar next time.

## What's next

- Optional URL reputation and TLS/DNS checks (clearly marked as external lookups)
- Screenshot/OCR input for messages received as images
- A shareable "safety card" a user can send to the person who forwarded the link
- Browser-extension wrapper that reuses the same `/api/analyze` contract

## Demo video (57 seconds, captioned)

A recorded walkthrough is in `docs/demo.mp4` and linked above. Longer script, if a live narration is preferred:

## Demo video script (2 minutes)

| Time | Shot | Line |
|---|---|---|
| 0:00–0:10 | Landing page | "This is PhishGuard AI. One field, one answer: is this link or message safe?" |
| 0:10–0:30 | Click the paypa1 quick prompt, Scan | "Real phishing URL. Score 90, critical. But the useful part is below." |
| 0:30–0:55 | Scroll through flags | "It caught the character swap, the .com lookalike, and the verify-account path — and explains each one." |
| 0:55–1:10 | Safe example (google.com) | "Same engine on a legitimate domain: score 8, safe, no false alarm." |
| 1:10–1:30 | Message tab, paste scam SMS | "Messages work the same way: urgency, credential request, link." |
| 1:30–1:50 | History + clear | "History stays in the browser. Nothing is stored server-side." |
| 1:50–2:00 | Repo/README | "Runs with zero API keys in demo mode, or with GPT. Repo and setup in the description." |

## Links

- Repo: https://github.com/Dhanush-sai-reddy/phishguard-ai
- Live demo: https://dhanush-sai-reddy.github.io/phishguard-ai/
- Video (57s captioned walkthrough): https://dhanush-sai-reddy.github.io/phishguard-ai/demo.mp4
- Screenshot: https://dhanush-sai-reddy.github.io/phishguard-ai/screenshot.png

---

## Disclosure (required by all three events)

PhishGuard AI was designed and built by Dhanush Sai Reddy between **21 and 23 October 2026**, inside the submission windows of NextSpark Hacks (Oct 21–26), SafeSpace Hacks (Oct 17–Nov 22), and LaunchPad Hacks (Oct 16–Nov 20). No code, design, or assets predate those windows. Third-party components: Vite, Express, OpenAI SDK (optional, unused without a key), Inter typeface, emoji icons. No user data is collected.

---

## Variant: LaunchPad Hacks 2026

LaunchPad scores Innovation & Originality, Usefulness & Impact, Implementation & Functionality, and (per the public page) presentation/demo quality, each 1–5.

**One-line pitch:** A phishing link checker that teaches the person why the link is fake, so they need it less next time.

**Why it fits "something worth launching":**
- Clear wedge: consumer security literacy, not another enterprise scanner.
- Zero-cost, zero-signup, works offline — the adoption barrier is one paste.
- Same engine powers an API, so a browser extension or school portal is a thin wrapper, not a rewrite.

**Demo path for judges (60 seconds):** open the live link → scan the `paypa1` example → read the two flag explanations → scan `google.com` → show the method & limits panel → show the local-only history.

**Honest limitations:** heuristic, text-only, no live reputation lookups (see the in-app panel). This is stated in the UI, not buried.

## Submission checklist

- [ ] Repo public, README has live link + run steps
- [ ] Live demo loads with `Demo Mode` badge and no console errors
- [ ] Video URL resolves (MP4 plays in the browser)
- [ ] Built-with tags added on Devpost
- [ ] Gallery image uploaded (`docs/screenshot.png`)
- [ ] Disclosure paragraph pasted where the form asks about prior work
- [ ] Submitted before deadline, confirmation screenshot saved
