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
3. If an API key is configured, the same input goes to an LLM with a strict JSON schema; any failure falls back to the heuristic result.
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

- Repo: `<add public GitHub URL>`
- Live demo: `<add deployed URL>`
- Video: `<add YouTube/Loom URL>`
