import dotenv from 'dotenv';
dotenv.config();

import express from 'express';
import cors from 'cors';
import OpenAI from 'openai';
import { getVerdictAndRisk, analyzeUrlDemo, analyzeMessageDemo } from '../analyzer.js';

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

// Random integer between min and max (inclusive)
function randomBetween(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

// Delay simulator for realistic demo experience (300-800ms)
function simulateDelay() {
  const delay = randomBetween(300, 800);
  return new Promise((resolve) => setTimeout(resolve, delay));
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
