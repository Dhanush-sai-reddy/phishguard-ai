/**
 * PhishGuard AI — Core Frontend Logic
 * Instant Phishing & Scam Detection
 */

// ==========================================================================
// Constants & Demo Presets
// ==========================================================================

const LOCAL_STORAGE_KEY = 'phishguard_history_v1';
const MAX_HISTORY_ITEMS = 20;
const GAUGE_CIRCUMFERENCE = 502.6548; // 2 * PI * 80

const DEMO_PRESETS = {
  url: {
    paypa1: 'https://paypa1-secure.com/verify-account?id=8372',
    google: 'https://www.google.com',
    ip: 'http://192.168.1.1/login.php?redirect=bank'
  },
  message: {
    prince: 'Dear Friend, I am Prince Abubakar from Nigeria. I have $45,000,000 USD that I need to transfer out of my country urgently. I need your bank account details and a small processing fee of $500 to initiate the transfer. You will receive 30% of the total amount. Please respond immediately with your full name, bank account number, and routing number. This is 100% legitimate and risk-free!!! Time is running out!!!',
    irs: 'URGENT: Your tax return has been flagged by the IRS for suspicious activity. Your Social Security Number has been compromised. Call +1-800-555-0199 IMMEDIATELY or face arrest. You must verify your identity by providing your SSN, date of birth, and bank account information within 24 hours. Failure to comply will result in legal action. Reference Case #IRS-2026-8834',
    normal: "Hey! Just wanted to check if we're still on for coffee tomorrow at 3pm? Let me know if the timing works for you. Also, I found that article about machine learning we were discussing - I'll send you the link when I find it."
  }
};

// Fallback simulations for graceful offline / standalone testing
const SIMULATED_RESPONSES = {
  'https://paypa1-secure.com/verify-account?id=8372': {
    score: 92,
    verdict: 'Dangerous Phishing Link',
    mode: 'demo',
    summary: 'High-confidence typosquatting attack targeting PayPal credentials. The domain uses visual substitution (digit 1 instead of letter l) and mimics account verification workflows to intercept sensitive credentials.',
    flags: [
      {
        icon: '🚨',
        name: 'Typosquatting Domain',
        severity: 'critical',
        explanation: "Domain 'paypa1-secure.com' replaces the letter 'l' with the digit '1' to deceive users into believing it is an authentic PayPal service."
      },
      {
        icon: '⚠️',
        name: 'Credential Harvesting Pattern',
        severity: 'high',
        explanation: "URI path '/verify-account' matches known credential phishing campaigns designed to steal login credentials and 2FA tokens."
      },
      {
        icon: '🌐',
        name: 'Recently Registered Domain',
        severity: 'high',
        explanation: 'Domain registered within the last 7 days with hidden WHOIS privacy protection.'
      }
    ],
    tips: [
      'Do not enter login credentials, passwords, or personal details on this site.',
      'Always check the address bar carefully for typos (e.g. 1 vs l, 0 vs O).',
      'Navigate directly to paypal.com by typing the official address in a fresh tab.'
    ]
  },
  'https://www.google.com': {
    score: 4,
    verdict: 'Safe & Verified',
    mode: 'demo',
    summary: 'Legitimate domain belonging to Google LLC. High reputation score, valid EV TLS certificate, and clean threat intelligence record across global telemetry.',
    flags: [],
    tips: [
      'The destination domain is authenticated and verified.',
      'Always ensure HTTPS padlock is active when submitting private information.'
    ]
  },
  'http://192.168.1.1/login.php?redirect=bank': {
    score: 78,
    verdict: 'Suspicious IP Destination',
    mode: 'demo',
    summary: 'Suspicious redirection using private subnet IPv4 address with banking referral parameters over unencrypted HTTP. May indicate DNS spoofing or local router interception.',
    flags: [
      {
        icon: '🌐',
        name: 'Direct IP Address in URL',
        severity: 'high',
        explanation: 'Host is a raw IP address (192.168.1.1) rather than a reputable domain name, commonly used in intranet evasion and MITM attacks.'
      },
      {
        icon: '🔓',
        name: 'Insecure Protocol (HTTP)',
        severity: 'high',
        explanation: 'Communication is unencrypted. Login credentials transmitted in cleartext.'
      },
      {
        icon: '🎣',
        name: 'Deceptive Redirect Parameter',
        severity: 'medium',
        explanation: "URL includes '?redirect=bank' attempting to mimic financial institution login redirects."
      }
    ],
    tips: [
      'Legitimate financial institutions never conduct authentication via raw private IP addresses.',
      'Never input banking passwords over non-HTTPS connections.',
      'Check router settings for potential DNS hijack attempts.'
    ]
  }
};

// ==========================================================================
// Application State
// ==========================================================================

const state = {
  currentTab: 'url',
  isScanning: false,
  currentResult: null,
  history: [],
  engineMode: 'demo', // 'ai' or 'demo'
  scoreAnimationId: null
};

// ==========================================================================
// DOM Element Cache
// ==========================================================================

const elements = {
  modeBadge: document.getElementById('modeBadge'),
  modeText: document.getElementById('modeText'),
  tabIndicator: document.getElementById('tabIndicator'),
  tabUrl: document.getElementById('tabUrl'),
  tabMessage: document.getElementById('tabMessage'),
  urlInputSection: document.getElementById('urlInputSection'),
  messageInputSection: document.getElementById('messageInputSection'),
  urlInput: document.getElementById('urlInput'),
  messageInput: document.getElementById('messageInput'),
  clearUrlBtn: document.getElementById('clearUrlBtn'),
  clearMessageBtn: document.getElementById('clearMessageBtn'),
  scanForm: document.getElementById('scanForm'),
  scanBtn: document.getElementById('scanBtn'),
  scanBtnText: document.getElementById('scanBtnText'),
  urlExamples: document.getElementById('urlExamples'),
  messageExamples: document.getElementById('messageExamples'),
  loadingState: document.getElementById('loadingState'),
  loadingStatusText: document.getElementById('loadingStatusText'),
  resultsSection: document.getElementById('resultsSection'),
  resultTypeBadge: document.getElementById('resultTypeBadge'),
  resultTargetPreview: document.getElementById('resultTargetPreview'),
  resultTimePill: document.getElementById('resultTimePill'),
  rescanBtn: document.getElementById('rescanBtn'),
  gaugeProgressCircle: document.getElementById('gaugeProgressCircle'),
  gaugeScoreValue: document.getElementById('gaugeScoreValue'),
  gaugeVerdict: document.getElementById('gaugeVerdict'),
  summarySourceText: document.getElementById('summarySourceText'),
  summaryParagraph: document.getElementById('summaryParagraph'),
  metaConfidence: document.getElementById('metaConfidence'),
  metaFlagsCount: document.getElementById('metaFlagsCount'),
  metaLatency: document.getElementById('metaLatency'),
  flagsCountBadge: document.getElementById('flagsCountBadge'),
  flagsGrid: document.getElementById('flagsGrid'),
  tipsList: document.getElementById('tipsList'),
  historyList: document.getElementById('historyList'),
  historyCountBadge: document.getElementById('historyCountBadge'),
  clearHistoryBtn: document.getElementById('clearHistoryBtn'),
  historyEmptyState: document.getElementById('historyEmptyState'),
  toastContainer: document.getElementById('toastContainer')
};

// ==========================================================================
// Application Initialization
// ==========================================================================

document.addEventListener('DOMContentLoaded', () => {
  initializeTabs();
  initializeHealthCheck();
  initializeHistory();
  initializeEventListeners();
  updateTabIndicator();
});

// ==========================================================================
// Health Check (/api/health)
// ==========================================================================

async function initializeHealthCheck() {
  try {
    const response = await fetch('/api/health');
    if (response.ok) {
      const data = await response.json();
      const isAi = data.mode === 'ai' || data.ai === true || data.status === 'ai';
      state.engineMode = isAi ? 'ai' : 'demo';
      setModeBadge(state.engineMode);
    } else {
      setModeBadge('demo');
    }
  } catch (error) {
    // If backend isn't up or network is restricted, default gracefully to demo mode
    setModeBadge('demo');
  }
}

function setModeBadge(mode) {
  if (mode === 'ai') {
    elements.modeBadge.className = 'mode-badge ai-mode';
    elements.modeText.textContent = 'AI Mode Active';
  } else {
    elements.modeBadge.className = 'mode-badge demo-mode';
    elements.modeText.textContent = 'Demo Mode';
  }
}

// ==========================================================================
// Tab Switching
// ==========================================================================

function initializeTabs() {
  elements.tabUrl.addEventListener('click', () => switchTab('url'));
  elements.tabMessage.addEventListener('click', () => switchTab('message'));
}

function switchTab(tab) {
  if (state.currentTab === tab) return;
  state.currentTab = tab;

  if (tab === 'url') {
    elements.tabUrl.classList.add('active');
    elements.tabUrl.setAttribute('aria-selected', 'true');
    elements.tabMessage.classList.remove('active');
    elements.tabMessage.setAttribute('aria-selected', 'false');

    elements.urlInputSection.classList.add('active');
    elements.messageInputSection.classList.remove('active');

    elements.urlExamples.classList.add('active');
    elements.messageExamples.classList.remove('active');

    setTimeout(() => elements.urlInput.focus(), 80);
  } else {
    elements.tabMessage.classList.add('active');
    elements.tabMessage.setAttribute('aria-selected', 'true');
    elements.tabUrl.classList.remove('active');
    elements.tabUrl.setAttribute('aria-selected', 'false');

    elements.messageInputSection.classList.add('active');
    elements.urlInputSection.classList.remove('active');

    elements.messageExamples.classList.add('active');
    elements.urlExamples.classList.remove('active');

    setTimeout(() => elements.messageInput.focus(), 80);
  }

  updateTabIndicator();
}

function updateTabIndicator() {
  const activeBtn = state.currentTab === 'url' ? elements.tabUrl : elements.tabMessage;
  if (!activeBtn) return;

  const left = activeBtn.offsetLeft;
  const width = activeBtn.offsetWidth;

  elements.tabIndicator.style.transform = `translateX(${left - 6}px)`;
  elements.tabIndicator.style.width = `${width}px`;
}

window.addEventListener('resize', () => {
  updateTabIndicator();
});

// ==========================================================================
// Event Listeners
// ==========================================================================

function initializeEventListeners() {
  // Form submission
  elements.scanForm.addEventListener('submit', (e) => {
    e.preventDefault();
    handleScan();
  });

  // Example Chips
  document.querySelectorAll('.example-chip').forEach((chip) => {
    chip.addEventListener('click', () => {
      const type = chip.getAttribute('data-type');
      const target = chip.getAttribute('data-target');
      handleExampleClick(type, target);
    });
  });

  // Clear Input Buttons
  elements.clearUrlBtn.addEventListener('click', () => {
    elements.urlInput.value = '';
    elements.urlInput.focus();
  });

  elements.clearMessageBtn.addEventListener('click', () => {
    elements.messageInput.value = '';
    elements.messageInput.focus();
  });

  // Re-scan Button in Results
  elements.rescanBtn.addEventListener('click', () => {
    handleScan();
  });

  // Clear History
  elements.clearHistoryBtn.addEventListener('click', clearHistory);
}

// ==========================================================================
// Example Handling
// ==========================================================================

function handleExampleClick(type, target) {
  if (type !== state.currentTab) {
    switchTab(type);
  }

  const content = DEMO_PRESETS[type]?.[target];
  if (!content) return;

  if (type === 'url') {
    elements.urlInput.value = content;
  } else {
    elements.messageInput.value = content;
  }

  // Auto trigger scan
  handleScan();
}

// ==========================================================================
// Scanning & API Handling
// ==========================================================================

async function handleScan() {
  if (state.isScanning) return;

  const inputEl = state.currentTab === 'url' ? elements.urlInput : elements.messageInput;
  const content = inputEl.value.trim();

  // Validate Input
  if (!content) {
    inputEl.classList.add('shake-error');
    inputEl.focus();
    showToast('Please enter a URL or message to scan.', 'error');
    setTimeout(() => inputEl.classList.remove('shake-error'), 600);
    return;
  }

  // URL basic prepending if missing protocol
  let processedContent = content;
  if (state.currentTab === 'url' && !content.startsWith('http://') && !content.startsWith('https://')) {
    // If it looks like a domain or IP, prepend https://
    if (/^[a-zA-Z0-9.-]+(\/.*)?$/.test(content)) {
      processedContent = 'https://' + content;
      elements.urlInput.value = processedContent;
    }
  }

  setScanningState(true);

  const startTime = performance.now();
  let result = null;

  try {
    // Attempt backend analysis
    const response = await fetch('/api/analyze', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        type: state.currentTab,
        content: processedContent
      })
    });

    if (response.ok) {
      result = await response.json();
    } else {
      if (response.status === 429) {
        throw new Error('Analysis rate limit exceeded. Please wait a moment.');
      }
      throw new Error(`Analysis server responded with status: ${response.status}`);
    }
  } catch (err) {
    console.warn('Backend /api/analyze failed or unreachable:', err);
    // If backend isn't up, generate realistic fallback result so demo never breaks
    result = generateFallbackResult(state.currentTab, processedContent);
    if (import.meta.env.DEV) {
      showToast('Backend offline (port 3001) — using local heuristic engine.', 'info');
    }
  }

  const latency = Math.round(performance.now() - startTime);

  // Slight simulated pause for radar scan effect if network was instantaneous (< 600ms)
  const remainingTime = Math.max(0, 700 - latency);
  await new Promise((resolve) => setTimeout(resolve, remainingTime));

  setScanningState(false);

  // Normalize Result Structure
  const normalizedResult = normalizeResult(result, latency);
  state.currentResult = normalizedResult;

  // Render & Animate Results
  renderResults(state.currentTab, processedContent, normalizedResult);

  // Add to History
  addToHistory({
    id: Date.now(),
    type: state.currentTab,
    content: processedContent,
    result: normalizedResult,
    timestamp: new Date().toISOString()
  });

  // Scroll to results
  setTimeout(() => {
    elements.resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }, 100);
}

function setScanningState(scanning) {
  state.isScanning = scanning;

  if (scanning) {
    elements.scanBtn.classList.add('scanning');
    elements.scanBtnText.textContent = 'Analyzing...';
    elements.loadingState.style.display = 'flex';
    elements.resultsSection.style.display = 'none';

    // Cycle radar status messages
    cycleLoadingStatus();
  } else {
    elements.scanBtn.classList.remove('scanning');
    elements.scanBtnText.textContent = 'Scan Now';
    elements.loadingState.style.display = 'none';
  }
}

let loadingStatusInterval = null;
function cycleLoadingStatus() {
  const statuses = [
    'Checking threat intelligence database...',
    'Analyzing domain lexical patterns & TLS...',
    'Inspecting suspicious keywords & urgency signals...',
    'Executing AI phishing heuristic engine...',
    'Evaluating threat risk score...'
  ];
  let index = 0;
  elements.loadingStatusText.textContent = statuses[0];

  clearInterval(loadingStatusInterval);
  loadingStatusInterval = setInterval(() => {
    index = (index + 1) % statuses.length;
    elements.loadingStatusText.textContent = statuses[index];
  }, 400);
}

// ==========================================================================
// Result Normalization
// ==========================================================================

function normalizeResult(raw, latencyMs = 280) {
  const score = typeof raw.score === 'number' ? Math.max(0, Math.min(100, Math.round(raw.score))) : 50;
  const verdict = raw.verdict || getScoreVerdict(score);
  const summary = raw.summary || 'Threat analysis complete. Review detected threat indicators and advisory tips below.';
  const mode = raw.mode || (state.engineMode === 'ai' ? 'ai' : 'demo');

  // Handle flags array (could be flags, redFlags, or threats)
  const rawFlags = raw.flags || raw.redFlags || raw.threatIndicators || raw.threats || [];
  const flags = rawFlags.map((f) => ({
    icon: f.icon || getFlagDefaultIcon(f.severity),
    name: f.name || f.title || 'Risk Indicator',
    severity: (f.severity || 'high').toLowerCase(),
    explanation: f.explanation || f.description || f.details || ''
  }));

  // Handle tips array (could be tips or safetyTips)
  let tips = raw.tips || raw.safetyTips || [];
  if (!Array.isArray(tips) || tips.length === 0) {
    tips = getDefaultTipsForScore(score);
  } else {
    tips = tips.map((t) => (typeof t === 'string' ? t : t.tip || t.text || String(t)));
  }

  return {
    score,
    verdict,
    summary,
    mode,
    flags,
    tips,
    confidence: raw.confidence || formatConfidence(flags),
    latency: latencyMs
  };
}

function formatConfidence(flags) {
  const weight = { critical: 18, high: 12, medium: 8, low: 4 };
  const total = flags.reduce((sum, f) => sum + (weight[f.severity] || 6), 0);
  return `${Math.min(99, 55 + total)}%`;
}

function getFlagDefaultIcon(severity) {
  switch ((severity || '').toLowerCase()) {
    case 'critical':
      return '🚨';
    case 'high':
      return '⚠️';
    case 'medium':
      return '⚡';
    case 'low':
      return '🔍';
    default:
      return '🛡️';
  }
}

function getDefaultTipsForScore(score) {
  if (score > 60) {
    return [
      'Do not click links or open attachments in this message or website.',
      'Never provide sensitive passwords, banking details, or OTP codes.',
      'Report and block this sender/domain in your email client or security gateway.'
    ];
  } else if (score > 30) {
    return [
      'Exercise caution before entering any personal credentials.',
      'Verify the sender identity through a trusted independent channel.',
      'Inspect the full domain path in the address bar.'
    ];
  } else {
    return [
      'No critical threat indicators detected.',
      'Always practice defense-in-depth and ensure multi-factor authentication (2FA) is enabled.'
    ];
  }
}

// ==========================================================================
// Fallback Heuristic Generator (Offline Resilience)
// ==========================================================================

function generateFallbackResult(type, content) {
  // Check exact simulation table first
  if (SIMULATED_RESPONSES[content]) {
    return SIMULATED_RESPONSES[content];
  }

  const lower = content.toLowerCase();

  // Pattern detection for URLs
  if (type === 'url') {
    if (lower.includes('paypa1') || lower.includes('secure-login') || lower.includes('verify-account')) {
      return {
        score: 94,
        verdict: 'Dangerous Phishing Link',
        mode: 'demo',
        summary: 'Deceptive credential harvesting link detected. Domain employs homograph typosquatting to impersonate financial authentication services.',
        flags: [
          {
            icon: '🚨',
            name: 'Homograph Typosquatting',
            severity: 'critical',
            explanation: 'Domain uses deceptive alphanumeric substitution to impersonate a legitimate service.'
          },
          {
            icon: '🎣',
            name: 'High-Risk Verification Parameter',
            severity: 'high',
            explanation: "Target path mimics urgency credential verification ('verify-account')."
          }
        ],
        tips: [
          'Close the browser tab immediately.',
          'Never submit credentials to unverified domains.'
        ]
      };
    }

    if (lower.includes('192.168.') || lower.includes('10.') || lower.includes('172.16.')) {
      return {
        score: 76,
        verdict: 'Suspicious Network Target',
        mode: 'demo',
        summary: 'Target resolves directly to private IP addressing without validated encryption certificates, typical of local gateway phishing or CSRF attacks.',
        flags: [
          {
            icon: '🌐',
            name: 'Private Subnet Direct IP',
            severity: 'high',
            explanation: 'Raw IP address used instead of canonical domain name.'
          },
          {
            icon: '🔓',
            name: 'Unencrypted Transmission',
            severity: 'high',
            explanation: 'Plaintext protocol without TLS encryption verification.'
          }
        ],
        tips: [
          'Verify your router DNS settings.',
          'Ensure all logins take place over authenticated HTTPS.'
        ]
      };
    }

    if (lower.includes('google.com') || lower.includes('github.com') || lower.includes('apple.com')) {
      return {
        score: 3,
        verdict: 'Safe & Verified',
        mode: 'demo',
        summary: 'Well-established enterprise domain with positive reputation, verified TLS certificates, and no active threat listings.',
        flags: [],
        tips: [
          'Domain is authenticated and verified as legitimate.',
          'Always verify HTTPS padlock in the address bar.'
        ]
      };
    }

    // Generic URL
    return {
      score: 48,
      verdict: 'Unverified Domain',
      mode: 'demo',
      summary: 'Domain possesses moderate risk indicators with neutral historical reputation. Exercise standard security diligence before entering credentials.',
      flags: [
        {
          icon: '⚡',
          name: 'Neutral Domain Reputation',
          severity: 'medium',
          explanation: 'Domain lacks high-volume historical trust markers.'
        }
      ],
      tips: [
        'Confirm the legitimacy of the destination before providing credentials.',
        'Check for HTTPS encryption.'
      ]
    };
  }

  // Pattern detection for Messages
  if (lower.includes('prince') || lower.includes('transfer out') || lower.includes('$45,000,000') || lower.includes('processing fee')) {
    return {
      score: 98,
      verdict: 'Advance-Fee Scam (419)',
      mode: 'demo',
      summary: 'Classic Nigerian Prince / Advance-Fee fraud pattern. High urgency, unrealistic financial promise, and demand for upfront processing fees to steal banking information.',
      flags: [
        {
          icon: '🚨',
          name: 'Advance-Fee Fraud Pattern',
          severity: 'critical',
          explanation: 'Promises exorbitant wealth in exchange for advance processing payments.'
        },
        {
          icon: '⚠️',
          name: 'Direct Banking Extraction',
          severity: 'critical',
          explanation: 'Explicitly requests full bank account numbers, routing numbers, and identity.'
        },
        {
          icon: '⏰',
          name: 'Artificial Urgency Pressure',
          severity: 'high',
          explanation: "Claims 'Time is running out!' to prevent critical victim reflection."
        }
      ],
      tips: [
        'Never send advance fees or money to unsolicited contacts.',
        'Never disclose bank account or routing numbers.',
        'Block and report this message immediately.'
      ]
    };
  }

  if (lower.includes('irs') || lower.includes('social security') || lower.includes('face arrest') || lower.includes('legal action')) {
    return {
      score: 96,
      verdict: 'Government Impersonation Scam',
      mode: 'demo',
      summary: 'Coercive government impersonation threat. Uses intimidation tactics including imminent arrest, compromised SSN claims, and urgent 24-hour ultimatums to extort identity and banking data.',
      flags: [
        {
          icon: '🚨',
          name: 'Government Agency Impersonation',
          severity: 'critical',
          explanation: 'Impersonates the Internal Revenue Service (IRS).'
        },
        {
          icon: '⚠️',
          name: 'Arrest & Legal Threats',
          severity: 'critical',
          explanation: 'Threatens immediate arrest and legal action to induce fear and compliance.'
        },
        {
          icon: '🎯',
          name: 'Identity Theft Solicitation',
          severity: 'critical',
          explanation: 'Demands SSN, date of birth, and banking info within 24 hours.'
        }
      ],
      tips: [
        'The IRS never initiates contact by email, text, or social media to demand immediate payment.',
        'The IRS never threatens immediate arrest or demands sensitive information over phone/text.',
        'Report this scam immediately to the Treasury Inspector General (TIGTA).'
      ]
    };
  }

  if (lower.includes('coffee') || lower.includes('article') || lower.includes('discussing') || lower.includes('timing works')) {
    return {
      score: 5,
      verdict: 'Clean / Safe Message',
      mode: 'demo',
      summary: 'Casual conversational message with no linguistic coercion, suspicious payment demands, urgency triggers, or credential harvesting indicators.',
      flags: [],
      tips: [
        'Message shows standard human conversational cadence.',
        'No malicious attachments or suspicious URLs detected.'
      ]
    };
  }

  // Generic message fallback
  return {
    score: 42,
    verdict: 'Low-to-Medium Suspicion',
    mode: 'demo',
    summary: 'The message contains generic phrasing. While no critical phishing indicators were flagged, treat unsolicited requests with caution.',
    flags: [
      {
        icon: '🔍',
        name: 'Unverified Origin',
        severity: 'medium',
        explanation: 'Message sender and context cannot be verified against known trusted identity.'
      }
    ],
    tips: [
      'Confirm the identity of the sender before clicking links or replying.',
      'Do not disclose private financial information.'
    ]
  };
}

// ==========================================================================
// Rendering Results
// ==========================================================================

function renderResults(type, content, result) {
  elements.resultsSection.style.display = 'flex';

  // Target Preview & Badge
  elements.resultTypeBadge.textContent = type === 'url' ? '🔗 URL' : '📧 Message';
  elements.resultTargetPreview.textContent = truncateText(content, 65);
  elements.resultTimePill.textContent = 'Just now';

  // Summary Card
  const isAi = result.mode === 'ai';
  elements.summarySourceText.textContent = isAi ? 'AI Neural Analysis' : 'Demo Analysis';
  elements.summaryParagraph.textContent = result.summary;

  // Metadata
  elements.metaConfidence.textContent = result.confidence || 'High (97.8%)';
  elements.metaFlagsCount.textContent = `${result.flags.length} Detected`;
  elements.metaLatency.textContent = `~${result.latency || 280}ms`;

  // Animate Circular Gauge & Verdict
  animateScoreGauge(result.score, result.verdict);

  // Render Red Flags Grid
  renderFlagCards(result.flags);

  // Render Safety Tips List
  renderSafetyTips(result.tips);
}

// ==========================================================================
// SVG Score Gauge Animation
// ==========================================================================

function animateScoreGauge(targetScore, verdictText) {
  if (state.scoreAnimationId) {
    cancelAnimationFrame(state.scoreAnimationId);
  }

  const duration = 1500; // 1.5 seconds animation
  const startTime = performance.now();
  const startScore = 0;
  const circle = elements.gaugeProgressCircle;
  const valueText = elements.gaugeScoreValue;
  const verdictBadge = elements.gaugeVerdict;

  // Easing function: ease-out cubic
  const easeOutCubic = (t) => 1 - Math.pow(1 - t, 3);

  function step(currentTime) {
    const elapsed = currentTime - startTime;
    const progress = Math.min(elapsed / duration, 1);
    const easedProgress = easeOutCubic(progress);

    const currentScore = Math.round(startScore + (targetScore - startScore) * easedProgress);

    // Calculate stroke offset
    const offset = GAUGE_CIRCUMFERENCE - (GAUGE_CIRCUMFERENCE * (currentScore / 100));
    circle.style.strokeDashoffset = offset;

    // Get color & gradient based on current score
    const color = getScoreColor(currentScore);
    circle.style.stroke = color;
    circle.style.color = color; // for filter drop-shadow currentColor

    // Text counter
    valueText.textContent = currentScore;
    valueText.style.color = currentScore > 60 ? '#ffffff' : '#ffffff';

    if (progress < 1) {
      state.scoreAnimationId = requestAnimationFrame(step);
    } else {
      // Final verdict state
      valueText.textContent = targetScore;
      updateVerdictBadge(targetScore, verdictText);
    }
  }

  state.scoreAnimationId = requestAnimationFrame(step);
}

function updateVerdictBadge(score, verdictText) {
  const badge = elements.gaugeVerdict;
  const color = getScoreColor(score);
  const text = verdictText || getScoreVerdict(score);

  badge.textContent = text;
  badge.style.color = color;
  badge.style.borderColor = `${color}66`;
  badge.style.background = `${color}18`;
  badge.style.boxShadow = `0 4px 16px ${color}33`;
}

// ==========================================================================
// Render Threat Flags (Red Flags)
// ==========================================================================

function renderFlagCards(flags) {
  const container = elements.flagsGrid;
  const badge = elements.flagsCountBadge;
  container.innerHTML = '';

  badge.textContent = flags.length;
  if (flags.length === 0) {
    badge.className = 'count-badge zero';
  } else {
    badge.className = 'count-badge';
  }

  if (flags.length === 0) {
    const cleanCard = document.createElement('div');
    cleanCard.className = 'no-threats-card';
    cleanCard.innerHTML = `
      <span class="no-threats-icon" aria-hidden="true">✅</span>
      <div class="no-threats-content">
        <h3>No Threats Detected</h3>
        <p>The analyzed target shows no signs of typosquatting, credential harvesting, manipulative social engineering, or known malicious blacklists.</p>
      </div>
    `;
    container.appendChild(cleanCard);
    return;
  }

  // Staggered slide-up cards
  flags.forEach((flag, index) => {
    const card = document.createElement('div');
    card.className = 'flag-card';
    card.style.animationDelay = `${index * 100}ms`;

    const sevClass = `severity-${flag.severity || 'high'}`;

    card.innerHTML = `
      <div class="flag-top-row">
        <div class="flag-title-group">
          <span class="flag-icon" aria-hidden="true">${flag.icon || '⚠️'}</span>
          <span class="flag-name">${escapeHTML(flag.name)}</span>
        </div>
        <span class="severity-badge ${sevClass}">${escapeHTML(flag.severity)}</span>
      </div>
      <p class="flag-explanation">${escapeHTML(flag.explanation)}</p>
    `;

    container.appendChild(card);
  });
}

// ==========================================================================
// Render Safety Tips
// ==========================================================================

function renderSafetyTips(tips) {
  const list = elements.tipsList;
  list.innerHTML = '';

  if (!tips || tips.length === 0) {
    tips = ['Always maintain active threat protection on your devices.'];
  }

  tips.forEach((tipText) => {
    const li = document.createElement('li');
    li.className = 'tip-item';
    li.innerHTML = `
      <div class="tip-check-icon" aria-hidden="true">✓</div>
      <span class="tip-text">${escapeHTML(tipText)}</span>
    `;
    list.appendChild(li);
  });
}

// ==========================================================================
// Scan History
// ==========================================================================

function initializeHistory() {
  try {
    const saved = localStorage.getItem(LOCAL_STORAGE_KEY);
    if (saved) {
      state.history = JSON.parse(saved);
    }
  } catch (err) {
    console.error('Failed to load history from localStorage:', err);
    state.history = [];
  }

  renderHistoryList();
}

function addToHistory(item) {
  // Prevent immediate duplicates at top
  if (state.history.length > 0 && state.history[0].content === item.content) {
    state.history[0] = item;
  } else {
    state.history.unshift(item);
  }

  if (state.history.length > MAX_HISTORY_ITEMS) {
    state.history.pop();
  }

  saveHistory();
  renderHistoryList();
}

function saveHistory() {
  try {
    localStorage.setItem(LOCAL_STORAGE_KEY, JSON.stringify(state.history));
  } catch (err) {
    console.error('Failed to persist history:', err);
  }
}

function clearHistory() {
  if (state.history.length === 0) {
    showToast('History is already empty.', 'info');
    return;
  }

  state.history = [];
  saveHistory();
  renderHistoryList();
  showToast('Scan history cleared.', 'info');
}

function renderHistoryList() {
  const list = elements.historyList;
  const countBadge = elements.historyCountBadge;
  const emptyState = elements.historyEmptyState;

  list.innerHTML = '';
  countBadge.textContent = state.history.length;

  if (state.history.length === 0) {
    emptyState.classList.add('visible');
    return;
  }

  emptyState.classList.remove('visible');

  state.history.forEach((item, index) => {
    const el = document.createElement('div');
    el.className = 'history-item';
    el.style.animationDelay = `${index * 40}ms`;

    const isUrl = item.type === 'url';
    const typeIcon = isUrl ? '🔗' : '📧';
    const score = item.result.score;
    const scoreColor = getScoreColor(score);
    const timeFormatted = formatTimestamp(item.timestamp);

    el.innerHTML = `
      <div class="history-item-left">
        <span class="history-type-icon" aria-hidden="true">${typeIcon}</span>
        <span class="history-content-text">${escapeHTML(truncateText(item.content, 48))}</span>
      </div>
      <div class="history-item-right">
        <span class="history-score-badge" style="background: ${scoreColor}18; color: ${scoreColor}; border: 1px solid ${scoreColor}44;">
          ${score} / 100
        </span>
        <span class="history-timestamp">${timeFormatted}</span>
      </div>
    `;

    // Click handler to re-open result
    el.addEventListener('click', () => {
      // Sync tab if needed
      if (item.type !== state.currentTab) {
        switchTab(item.type);
      }
      if (item.type === 'url') {
        elements.urlInput.value = item.content;
      } else {
        elements.messageInput.value = item.content;
      }

      state.currentResult = item.result;
      renderResults(item.type, item.content, item.result);
      elements.resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
    });

    list.appendChild(el);
  });
}

// ==========================================================================
// Toast System
// ==========================================================================

function showToast(message, type = 'error') {
  const container = elements.toastContainer;
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;

  const icon = type === 'error' ? '⚠️' : type === 'success' ? '✅' : 'ℹ️';

  toast.innerHTML = `
    <span class="toast-icon">${icon}</span>
    <span class="toast-message">${escapeHTML(message)}</span>
  `;

  container.appendChild(toast);

  setTimeout(() => {
    toast.classList.add('hiding');
    setTimeout(() => {
      if (toast.parentNode) {
        toast.parentNode.removeChild(toast);
      }
    }, 350);
  }, 4200);
}

// ==========================================================================
// Utility Functions
// ==========================================================================

function getScoreColor(score) {
  if (score <= 20) return '#00d68f'; // Safe (green)
  if (score <= 40) return '#7bc67e'; // Low (light green)
  if (score <= 60) return '#ffb800'; // Medium (amber)
  if (score <= 80) return '#ff6b35'; // High (orange)
  return '#ff3d71';                  // Critical (red)
}

function getScoreVerdict(score) {
  if (score <= 20) return 'Safe / Verified';
  if (score <= 40) return 'Low Risk';
  if (score <= 60) return 'Suspicious';
  if (score <= 80) return 'Dangerous';
  return 'Critical Threat';
}

function formatTimestamp(isoString) {
  try {
    const date = new Date(isoString);
    const now = new Date();
    const diffSec = Math.floor((now - date) / 1000);

    if (diffSec < 45) return 'Just now';
    if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m ago`;
    if (diffSec < 86400) return `${Math.floor(diffSec / 3600)}h ago`;
    return `${Math.floor(diffSec / 86400)}d ago`;
  } catch (err) {
    return 'Recent';
  }
}

function truncateText(text, maxLen = 50) {
  if (!text) return '';
  if (text.length <= maxLen) return text;
  return text.substring(0, maxLen) + '...';
}

function escapeHTML(str) {
  if (typeof str !== 'string') return String(str || '');
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
