import dotenv from 'dotenv';
dotenv.config();

import express from 'express';
import cors from 'cors';
import OpenAI from 'openai';

const app = express();
const PORT = process.env.PORT || 3001;
const OPENAI_API_KEY = process.env.OPENAI_API_KEY?.trim();
const isAiMode = Boolean(OPENAI_API_KEY);

const openai = isAiMode
  ? new OpenAI({ apiKey: OPENAI_API_KEY })
  : null;

// CORS configuration allowing frontend origin
app.use(
  cors({
    origin: ['http://localhost:5173', 'http://127.0.0.1:5173'],
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
  })
);

app.use(express.json());

// In-memory rate limiter (max 20 requests per minute per IP)
const rateLimitMap = new Map();
const RATE_LIMIT_WINDOW_MS = 60 * 1000;
const RATE_LIMIT_MAX_REQUESTS = 20;

// Periodic cleanup of rate limiter map
setInterval(() => {
  const now = Date.now();
  for (const [ip, record] of rateLimitMap.entries()) {
    if (now > record.resetTime) {
      rateLimitMap.delete(ip);
    }
  }
}, 5 * 60 * 1000).unref();

function rateLimiter(req, res, next) {
  const forwarded = req.headers['x-forwarded-for'];
  const ip = (typeof forwarded === 'string' ? forwarded.split(',')[0].trim() : null) ||
    req.socket.remoteAddress ||
    '127.0.0.1';

  const now = Date.now();
  let record = rateLimitMap.get(ip);

  if (!record || now > record.resetTime) {
    record = { count: 1, resetTime: now + RATE_LIMIT_WINDOW_MS };
    rateLimitMap.set(ip, record);
    return next();
  }

  record.count += 1;
  if (record.count > RATE_LIMIT_MAX_REQUESTS) {
    return res.status(429).json({
      error: 'Too many requests. Please wait a minute before analyzing more content.',
    });
  }

  next();
}

app.use('/api/', rateLimiter);

// Helper function to map score to verdict and riskLevel
function getVerdictAndRisk(score) {
  const clamped = Math.max(0, Math.min(100, Math.round(score)));
  if (clamped <= 20) {
    return { score: clamped, verdict: 'Safe', riskLevel: 'safe' };
  } else if (clamped <= 40) {
    return { score: clamped, verdict: 'Low Risk', riskLevel: 'low' };
  } else if (clamped <= 60) {
    return { score: clamped, verdict: 'Suspicious', riskLevel: 'medium' };
  } else if (clamped <= 80) {
    return { score: clamped, verdict: 'Dangerous', riskLevel: 'high' };
  } else {
    return { score: clamped, verdict: 'Critical Threat', riskLevel: 'critical' };
  }
}

// Random integer between min and max (inclusive)
function randomBetween(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

// Delay simulator for realistic demo experience (300-800ms)
function simulateDelay() {
  const delay = randomBetween(300, 800);
  return new Promise((resolve) => setTimeout(resolve, delay));
}

// Demo pattern matching for URLs
function analyzeUrlDemo(urlInput) {
  let hostname = '';
  let pathname = '';
  const rawInput = urlInput.trim();

  try {
    const parsed = new URL(rawInput.includes('://') ? rawInput : `http://${rawInput}`);
    hostname = parsed.hostname.toLowerCase();
    pathname = parsed.pathname.toLowerCase();
  } catch {
    hostname = rawInput.toLowerCase().split('/')[0];
    pathname = rawInput.toLowerCase().slice(hostname.length);
  }

  const flags = [];
  let threatScore = 0;

  // 1. Typosquatting of popular domains
  const typosquattingPatterns = [
    { typo: 'paypa1', legit: 'paypal.com' },
    { typo: 'g00gle', legit: 'google.com' },
    { typo: 'amaz0n', legit: 'amazon.com' },
    { typo: 'micros0ft', legit: 'microsoft.com' },
    { typo: 'faceb00k', legit: 'facebook.com' },
    { typo: 'netfliix', legit: 'netflix.com' },
    { typo: 'appie', legit: 'apple.com' },
    { typo: 'instgram', legit: 'instagram.com' },
  ];

  const matchedTypo = typosquattingPatterns.find((pattern) =>
    hostname.includes(pattern.typo)
  );

  if (matchedTypo) {
    threatScore = Math.max(threatScore, 90);
    flags.push({
      name: 'Typosquatting Detected',
      severity: 'high',
      explanation: `The domain '${hostname}' closely mimics legitimate '${matchedTypo.legit}' using character substitution to deceive users.`,
      icon: '⚠️',
    });
  }

  // 2. IP addresses instead of domain names
  const ipv4Regex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
  const isIp = ipv4Regex.test(hostname) || hostname.startsWith('[') || /^[0-9.]+(:\d+)?$/.test(hostname);
  if (isIp) {
    threatScore = Math.max(threatScore, 85);
    flags.push({
      name: 'Direct IP Host',
      severity: 'high',
      explanation: `The URL connects directly to raw IP address '${hostname}' instead of a registered domain name, common in malicious drop sites.`,
      icon: '🔴',
    });
  }

  // 3. Suspicious TLDs
  const suspiciousTlds = [
    '.xyz', '.tk', '.ml', '.ga', '.cf', '.buzz', '.top', '.click', '.link', '.work',
  ];
  const matchedTld = suspiciousTlds.find((tld) => hostname.endsWith(tld));
  if (matchedTld) {
    threatScore = Math.max(threatScore, 72);
    flags.push({
      name: 'Suspicious Top-Level Domain',
      severity: 'high',
      explanation: `Uses '${matchedTld}', a TLD with minimal registration verification that is frequently abused for disposable phishing campaigns.`,
      icon: '🌐',
    });
  }

  // 4. Excessive subdomains (more than 3 dots in hostname)
  const dotCount = (hostname.match(/\./g) || []).length;
  if (dotCount > 3) {
    threatScore = Math.max(threatScore, 62);
    flags.push({
      name: 'Excessive Subdomains',
      severity: 'medium',
      explanation: `The domain structure contains ${dotCount} subdomains, a technique frequently used to mask the actual root destination.`,
      icon: '🔍',
    });
  }

  // 5. Sensitive path keywords
  const pathKeywords = [
    'login', 'verify', 'secure', 'account', 'update', 'confirm', 'suspend',
  ];
  const matchedKeywords = pathKeywords.filter((kw) => pathname.includes(kw));
  if (matchedKeywords.length > 0) {
    threatScore = Math.max(threatScore, 58);
    flags.push({
      name: 'Credential Harvesting Keywords',
      severity: 'medium',
      explanation: `The path contains sensitive keywords (${matchedKeywords.map((k) => `'${k}'`).join(', ')}) commonly found on account takeover portals.`,
      icon: '🔒',
    });
  }

  // 6. Well-known trusted domains
  const trustedDomains = [
    'google.com',
    'github.com',
    'youtube.com',
    'wikipedia.org',
    'amazon.com',
    'paypal.com',
    'microsoft.com',
    'apple.com',
    'facebook.com',
    'netflix.com',
    'instagram.com',
    'linkedin.com',
    'twitter.com',
    'x.com',
  ];

  const isTrusted =
    flags.length === 0 &&
    trustedDomains.some(
      (td) => hostname === td || hostname.endsWith(`.${td}`)
    );

  if (isTrusted) {
    threatScore = 8;
    flags.push({
      name: 'Verified Trusted Domain',
      severity: 'low',
      explanation: `The domain '${hostname}' belongs to a verified, highly-trusted organization with standard TLS practices.`,
      icon: '🟢',
    });
  } else if (flags.length === 0) {
    // 7. Otherwise return low threat
    threatScore = 28;
    flags.push({
      name: 'Unindexed / Standard Domain',
      severity: 'low',
      explanation: 'No immediate red flags or typosquatting patterns detected, but always verify origin before authenticating.',
      icon: '🔍',
    });
  }

  const { score, verdict, riskLevel } = getVerdictAndRisk(threatScore);

  let summary = '';
  let tips = [];

  if (riskLevel === 'critical' || riskLevel === 'high') {
    summary = `High-risk indicators detected for this URL, including ${flags.map((f) => f.name.toLowerCase()).join(' and ')}. Navigating to this destination poses an immediate threat of credential theft or malware download.`;
    tips = [
      'Do not enter passwords, email addresses, or payment details on this website.',
      'Check the address bar closely to ensure the domain matches the official brand name exactly.',
      'Navigate to the service manually by typing their known official web address.',
    ];
  } else if (riskLevel === 'medium') {
    summary = `This URL contains suspicious structural characteristics such as sensitive keywords or multiple subdomain layers. Proceed with heightened caution.`;
    tips = [
      'Confirm the sender or referral source before clicking or logging in.',
      'Inspect the SSL certificate to ensure it is registered to the expected entity.',
    ];
  } else {
    summary = `This URL appears safe with no obvious phishing triggers. It matches standard trusted domain structures or exhibits low threat indicators.`;
    tips = [
      'Always ensure HTTPS is active before transmitting any personal information.',
      'Bookmark frequently used websites to avoid navigation through search or third-party links.',
    ];
  }

  return {
    score,
    verdict,
    riskLevel,
    flags,
    summary,
    tips,
    mode: 'demo',
  };
}

// Demo pattern matching for Messages
function analyzeMessageDemo(messageInput) {
  const lower = messageInput.toLowerCase();
  const flags = [];
  let scoreDelta = 0;

  // 1. Urgency words
  const urgencyWords = [
    'urgent',
    'immediately',
    'suspended',
    'verify now',
    'act now',
    'limited time',
    '24 hours',
    'account will be',
  ];
  const matchedUrgency = urgencyWords.filter((w) => lower.includes(w));
  if (matchedUrgency.length > 0) {
    scoreDelta += 21;
    flags.push({
      name: 'Manufactured Urgency',
      severity: 'high',
      explanation: `Contains urgent pressure triggers (${matchedUrgency.map((u) => `"${u}"`).join(', ')}) designed to bypass critical thinking and force rash actions.`,
      icon: '⚠️',
    });
  }

  // 2. Money/prize claims
  const prizeWords = [
    'won',
    'winner',
    'lottery',
    'million',
    'inheritance',
    'prince',
    'bitcoin',
    'crypto',
    'investment',
  ];
  const matchedPrize = prizeWords.filter((w) =>
    new RegExp(`\\b${w}\\b`, 'i').test(lower)
  );
  if (matchedPrize.length > 0) {
    scoreDelta += 22;
    flags.push({
      name: 'Unrealistic Financial Incentive',
      severity: 'high',
      explanation: `Prompts claims of unexpected windfalls or high-return investments (${matchedPrize.map((p) => `"${p}"`).join(', ')}), typical of financial scams.`,
      icon: '💰',
    });
  }

  // 3. Credential requests
  const credentialWords = [
    'password',
    'ssn',
    'social security',
    'credit card',
    'bank account',
    'routing number',
    'pin',
  ];
  const matchedCredentials = credentialWords.filter((w) => lower.includes(w));
  if (matchedCredentials.length > 0) {
    scoreDelta += 23;
    flags.push({
      name: 'Sensitive Credential Request',
      severity: 'high',
      explanation: `Explicitly requests confidential identity or banking data (${matchedCredentials.map((c) => `"${c}"`).join(', ')}). Legitimate companies never solicit these via plain message.`,
      icon: '🔒',
    });
  }

  // 4. Impersonation
  const impersonationWords = [
    'irs',
    'fbi',
    'police',
    'microsoft support',
    'apple support',
    'tech support',
    'customer service',
  ];
  const matchedImpersonation = impersonationWords.filter((w) => lower.includes(w));
  if (matchedImpersonation.length > 0) {
    scoreDelta += 19;
    flags.push({
      name: 'Authority / Brand Impersonation',
      severity: 'high',
      explanation: `References known institutions or technical desks (${matchedImpersonation.map((i) => `"${i}"`).join(', ')}) to intimidate or manipulate trust.`,
      icon: '🎭',
    });
  }

  // 5. Poor grammar / formatting patterns
  const hasExclamations = /!{2,}/.test(messageInput);
  const hasMultipleDollars = /(\$[0-9]+.*\$|\${2,})/.test(messageInput);
  const words = messageInput.split(/\s+/);
  const capsWords = words.filter(
    (w) => w.length >= 4 && w === w.toUpperCase() && /[A-Z]/.test(w)
  );
  const hasExcessiveCaps = capsWords.length >= 2;

  if (hasExclamations || hasMultipleDollars || hasExcessiveCaps) {
    scoreDelta += 17;
    const grammarDetails = [];
    if (hasExclamations) grammarDetails.push('multiple exclamation points');
    if (hasMultipleDollars) grammarDetails.push('repeated dollar signs');
    if (hasExcessiveCaps) grammarDetails.push('aggressive ALL-CAPS text');

    flags.push({
      name: 'Unprofessional Syntax & Formatting',
      severity: 'medium',
      explanation: `Message exhibits suspicious formatting cues (${grammarDetails.join(', ')}) characteristic of automated spam templates.`,
      icon: '📧',
    });
  }

  let finalScore = 0;
  if (flags.length === 0) {
    finalScore = 8;
    flags.push({
      name: 'Standard Legitimate Tone',
      severity: 'low',
      explanation: 'No pressure tactics, credential harvesting phrases, or obvious scam phrasing were identified.',
      icon: '🟢',
    });
  } else {
    finalScore = Math.min(96, 10 + scoreDelta);
  }

  const { score, verdict, riskLevel } = getVerdictAndRisk(finalScore);

  let summary = '';
  let tips = [];

  if (riskLevel === 'critical' || riskLevel === 'high') {
    summary = `The message matches multiple known social engineering techniques, focusing on urgency and credential solicitation. Treat this communication as a dangerous attack vector.`;
    tips = [
      'Never reply to unsolicited communications asking for sensitive credentials or urgent action.',
      'Do not click links or call phone numbers contained directly within the message.',
      'Contact the institution through their official, independently-verified helpline.',
    ];
  } else if (riskLevel === 'medium') {
    summary = `The message contains suspicious keywords or informal pressure formatting. Exercise caution before clicking embedded links or providing information.`;
    tips = [
      'Verify the actual sender email address or phone number, not just the displayed contact name.',
      'Be wary of unprompted notifications requesting status updates.',
    ];
  } else {
    summary = `The message shows no significant signs of phishing or deceptive social engineering. It appears routine and low risk.`;
    tips = [
      'Continue following safe communication hygiene.',
      'Remember that legitimate organizations never ask for your password via message.',
    ];
  }

  return {
    score,
    verdict,
    riskLevel,
    flags,
    summary,
    tips,
    mode: 'demo',
  };
}

// AI Mode analysis using OpenAI GPT-4o-mini
async function analyzeWithAi(type, content) {
  const systemPrompt = `You are an expert cybersecurity analyst specializing in phishing detection, URL analysis, and social engineering threat assessment.
Analyze the provided ${type === 'url' ? 'URL' : 'message'} for phishing, scam, and social engineering indicators.
Be thorough, objective, and educational, but avoid being unnecessarily alarmist.

You must respond with a JSON object strictly following this schema:
{
  "score": <integer from 0 to 100>,
  "verdict": "<Safe | Low Risk | Suspicious | Dangerous | Critical Threat>",
  "riskLevel": "<safe | low | medium | high | critical>",
  "flags": [
    {
      "name": "<concise title of the detected indicator>",
      "severity": "<high | medium | low>",
      "explanation": "<detailed plain-English explanation of why this was flagged>",
      "icon": "<one emoji from: ⚠️, 🔴, 🟡, 🟢, 🔍, 🎭, 💰, 🔒, 📧, 🌐>"
    }
  ],
  "summary": "<2-3 sentence plain-English summary of the security analysis>",
  "tips": [
    "<actionable educational advice 1>",
    "<actionable educational advice 2>"
  ]
}

Score, verdict, and riskLevel must strictly follow these ranges:
- 0 to 20: verdict "Safe", riskLevel "safe"
- 21 to 40: verdict "Low Risk", riskLevel "low"
- 41 to 60: verdict "Suspicious", riskLevel "medium"
- 61 to 80: verdict "Dangerous", riskLevel "high"
- 81 to 100: verdict "Critical Threat", riskLevel "critical"`;

  const userPrompt = `Please analyze this ${type}:\n\n${content}`;

  const completion = await openai.chat.completions.create({
    model: 'gpt-4o-mini',
    response_format: { type: 'json_object' },
    messages: [
      { role: 'system', content: systemPrompt },
      { role: 'user', content: userPrompt },
    ],
    temperature: 0.2,
  });

  const parsed = JSON.parse(completion.choices[0].message.content);

  // Normalize and enforce score and riskLevel consistency
  const score = typeof parsed.score === 'number' ? parsed.score : 20;
  const { verdict, riskLevel } = getVerdictAndRisk(score);

  return {
    score,
    verdict,
    riskLevel,
    flags: Array.isArray(parsed.flags) ? parsed.flags : [],
    summary: parsed.summary || 'Security analysis complete.',
    tips: Array.isArray(parsed.tips) && parsed.tips.length > 0
      ? parsed.tips
      : ['Never share sensitive credentials in response to unverified requests.'],
    mode: 'ai',
  };
}

// Health endpoint
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    mode: isAiMode ? 'ai' : 'demo',
  });
});

// Analyze endpoint
app.post('/api/analyze', async (req, res) => {
  try {
    const { type, content } = req.body || {};

    if (!type || (type !== 'url' && type !== 'message')) {
      return res.status(400).json({
        error: 'Invalid request: "type" must be either "url" or "message".',
      });
    }

    if (!content || typeof content !== 'string' || content.trim().length === 0) {
      return res.status(400).json({
        error: 'Invalid request: "content" must be a non-empty string.',
      });
    }

    const trimmedContent = content.trim();

    if (isAiMode) {
      try {
        const aiResult = await analyzeWithAi(type, trimmedContent);
        return res.json(aiResult);
      } catch (aiError) {
        console.error('OpenAI analysis error, falling back to demo mode:', aiError.message);
        // Fall back gracefully to demo analysis if AI call fails
        await simulateDelay();
        const fallbackResult =
          type === 'url'
            ? analyzeUrlDemo(trimmedContent)
            : analyzeMessageDemo(trimmedContent);
        return res.json(fallbackResult);
      }
    } else {
      // Demo mode
      await simulateDelay();
      const demoResult =
        type === 'url'
          ? analyzeUrlDemo(trimmedContent)
          : analyzeMessageDemo(trimmedContent);
      return res.json(demoResult);
    }
  } catch (error) {
    console.error('Error handling /api/analyze:', error);
    return res.status(500).json({
      error: 'An internal error occurred while processing the security analysis.',
    });
  }
});

// Start server
app.listen(PORT, () => {
  const modeLabel = isAiMode ? 'ai mode' : 'demo mode';
  console.log(`🛡️ PhishGuard AI server running on port ${PORT} (${modeLabel})`);
});
