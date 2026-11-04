/**
 * PhishGuard AI — Core Frontend Logic
 * Instant Phishing & Scam Detection
 */

// ==========================================================================
// Constants & Demo Presets
// ==========================================================================

import { analyzeUrlDemo, analyzeMessageDemo, getVerdictAndRisk } from './analyzer.js';
import Tesseract from 'tesseract.js';
import jsQR from 'jsqr';
import QRCode from 'qrcode';

const LOCAL_STORAGE_KEY = 'phishguard_history_v1';
const MAX_HISTORY_ITEMS = 20;
const GAUGE_CIRCUMFERENCE = 502.6548; // 2 * PI * 80

// Tesseract worker cache
let tesseractWorker = null;

const DEMO_PRESETS = {
  url: {
    paypa1: 'https://paypa1-secure.com/verify-account?id=8372',
    google: 'https://www.google.com',
    ip: 'http://192.168.1.1/login.php?redirect=bank',
    at: 'https://paypal.com@attacker.example/verify'
  },
  message: {
    prince: 'Dear Friend, I am Prince Abubakar from Nigeria. I have $45,000,000 USD that I need to transfer out of my country urgently. I need your bank account details and a small processing fee of $500 to initiate the transfer. You will receive 30% of the total amount. Please respond immediately with your full name, bank account number, and routing number. This is 100% legitimate and risk-free!!! Time is running out!!!',
    irs: 'URGENT: Your tax return has been flagged by the IRS for suspicious activity. Your Social Security Number has been compromised. Call +1-800-555-0199 IMMEDIATELY or face arrest. You must verify your identity by providing your SSN, date of birth, and bank account information within 24 hours. Failure to comply will result in legal action. Reference Case #IRS-2026-8834',
    normal: "Hey! Just wanted to check if we're still on for coffee tomorrow at 3pm? Let me know if the timing works for you. Also, I found that article about machine learning we were discussing - I'll send you the link when I find it."
  },
  screenshot: {
    phishing: 'phishing',
    qr: 'qr',
    legit: 'legit'
  }
};

// Fallback simulations for graceful offline / standalone testing
// Empty string = same-origin backend (dev proxy). null = static-only demo.
const API_BASE = import.meta.env.VITE_API_URL ?? (import.meta.env.DEV ? '' : null);



// ==========================================================================
// Application State
// ==========================================================================

const state = {
  currentTab: 'url',
  isScanning: false,
  currentResult: null,
  history: [],
  engineMode: 'demo', // 'ai' or 'demo'
  scoreAnimationId: null,
  // Screenshot state
  screenshotFile: null,
  screenshotImage: null,
  extractedText: '',
  extractedLinks: [],
  qrContent: '',
  ocrWorkerReady: false
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
  tabScreenshot: document.getElementById('tabScreenshot'),
  urlInputSection: document.getElementById('urlInputSection'),
  messageInputSection: document.getElementById('messageInputSection'),
  screenshotInputSection: document.getElementById('screenshotInputSection'),
  urlInput: document.getElementById('urlInput'),
  messageInput: document.getElementById('messageInput'),
  clearUrlBtn: document.getElementById('clearUrlBtn'),
  clearMessageBtn: document.getElementById('clearMessageBtn'),
  scanForm: document.getElementById('scanForm'),
  scanBtn: document.getElementById('scanBtn'),
  scanBtnText: document.getElementById('scanBtnText'),
  urlExamples: document.getElementById('urlExamples'),
  messageExamples: document.getElementById('messageExamples'),
  screenshotExamples: document.getElementById('screenshotExamples'),
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
  toastContainer: document.getElementById('toastContainer'),
  // Screenshot elements
  screenshotDropzone: document.getElementById('screenshotDropzone'),
  screenshotFileInput: document.getElementById('screenshotFileInput'),
  imagePreview: document.getElementById('imagePreview'),
  previewImage: document.getElementById('previewImage'),
  removeImageBtn: document.getElementById('removeImageBtn'),
  ocrProgress: document.getElementById('ocrProgress'),
  progressBar: document.getElementById('progressBar'),
  progressStatus: document.getElementById('progressStatus'),
  progressDetail: document.getElementById('progressDetail'),
  extractedContent: document.getElementById('extractedContent'),
  extractedText: document.getElementById('extractedText'),
  ocrMethodBadge: document.getElementById('ocrMethodBadge'),
  copyTextBtn: document.getElementById('copyTextBtn'),
  linksSection: document.getElementById('linksSection'),
  linksList: document.getElementById('linksList'),
  linkCountBadge: document.getElementById('linkCountBadge'),
  qrSection: document.getElementById('qrSection'),
  qrContent: document.getElementById('qrContent'),
  qrStatusBadge: document.getElementById('qrStatusBadge'),
  scanExtractedBtn: document.getElementById('scanExtractedBtn'),
  screenshotError: document.getElementById('screenshotError'),
  errorMessage: document.getElementById('errorMessage'),
  retryBtn: document.getElementById('retryBtn'),
  // Voice elements
  tabVoice: document.getElementById('tabVoice'),
  voiceInputSection: document.getElementById('voiceInputSection'),
  voiceExamples: document.getElementById('voiceExamples'),
  recordBtn: document.getElementById('recordBtn'),
  recordLabel: document.getElementById('recordLabel'),
  recordTimer: document.getElementById('recordTimer'),
  voiceFileInput: document.getElementById('voiceFileInput'),
  voiceStatus: document.getElementById('voiceStatus'),
  voiceTranscriptBox: document.getElementById('voiceTranscriptBox'),
  voiceTranscript: document.getElementById('voiceTranscript'),
  voiceLangBadge: document.getElementById('voiceLangBadge'),
  voicePlayAlertBtn: document.getElementById('voicePlayAlertBtn')
};

// ==========================================================================
// Application Initialization
// ==========================================================================


// ==========================================================================
// Method & limits modal
// ==========================================================================

function initializeInfoModal() {
  const modal = document.getElementById('infoModal');
  const openBtn = document.getElementById('openInfo');
  const closeBtn = document.getElementById('closeInfo');
  if (!modal || !openBtn || !closeBtn) return;

  const open = () => {
    modal.hidden = false;
    document.body.style.overflow = 'hidden';
    closeBtn.focus();
  };

  const close = () => {
    modal.hidden = true;
    document.body.style.overflow = '';
    openBtn.focus();
  };

  openBtn.addEventListener('click', open);
  closeBtn.addEventListener('click', close);
  modal.addEventListener('click', (event) => {
    if (event.target === modal) close();
  });
  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape' && !modal.hidden) close();
  });
}

document.addEventListener('DOMContentLoaded', () => {
  initializeTabs();
  initializeHealthCheck();
  initializeHistory();
  initializeEventListeners();
  initializeInfoModal();
  initializeVoiceTab();
  updateTabIndicator();
});

// ==========================================================================
// Health Check (/api/health)
// ==========================================================================

async function initializeHealthCheck() {
  if (API_BASE === null) {
    setModeBadge('demo');
    return;
  }

  try {
    const response = await fetch(`${API_BASE}/api/health`);
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

const TAB_IDS = ['url', 'message', 'screenshot', 'voice'];

function tabButtonId(tab) {
  return 'tab' + tab.charAt(0).toUpperCase() + tab.slice(1);
}

function tabSectionId(tab) {
  return tab + 'InputSection';
}

function tabExamplesId(tab) {
  return tab + 'Examples';
}

function initializeTabs() {
  TAB_IDS.forEach((tab) => {
    elements[tabButtonId(tab)].addEventListener('click', () => switchTab(tab));
  });
}

function switchTab(tab) {
  if (state.currentTab === tab) return;
  state.currentTab = tab;

  TAB_IDS.forEach((t) => {
    const btn = elements[tabButtonId(t)];
    const isActive = t === tab;
    btn.classList.toggle('active', isActive);
    btn.setAttribute('aria-selected', String(isActive));
    elements[tabSectionId(t)].classList.toggle('active', isActive);
    const examples = elements[tabExamplesId(t)];
    if (examples) examples.classList.toggle('active', isActive);
  });

  if (tab === 'url') setTimeout(() => elements.urlInput.focus(), 80);
  if (tab === 'message') setTimeout(() => elements.messageInput.focus(), 80);

  // Initialize OCR worker on first visit
  if (tab === 'screenshot' && !state.ocrWorkerReady) {
    initializeOCRWorker();
  }

  updateTabIndicator();
}

function updateTabIndicator() {
  const activeBtn = elements[tabButtonId(state.currentTab)];
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

  // Screenshot Dropzone
  elements.screenshotDropzone.addEventListener('click', () => elements.screenshotFileInput.click());
  elements.screenshotDropzone.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      elements.screenshotFileInput.click();
    }
  });
  elements.screenshotDropzone.addEventListener('dragover', (e) => {
    e.preventDefault();
    elements.screenshotDropzone.classList.add('drag-over');
  });
  elements.screenshotDropzone.addEventListener('dragleave', () => {
    elements.screenshotDropzone.classList.remove('drag-over');
  });
  elements.screenshotDropzone.addEventListener('drop', (e) => {
    e.preventDefault();
    elements.screenshotDropzone.classList.remove('drag-over');
    if (e.dataTransfer.files.length > 0) {
      handleScreenshotFile(e.dataTransfer.files[0]);
    }
  });
  elements.screenshotFileInput.addEventListener('change', (e) => {
    if (e.target.files.length > 0) {
      handleScreenshotFile(e.target.files[0]);
    }
  });

  // Remove Image
  elements.removeImageBtn.addEventListener('click', clearScreenshot);

  // Copy Extracted Text
  elements.copyTextBtn.addEventListener('click', copyExtractedText);

  // Scan Extracted Content
  elements.scanExtractedBtn.addEventListener('click', handleScanExtracted);

  // Retry Button
  elements.retryBtn.addEventListener('click', clearScreenshot);
}

// ==========================================================================
// Example Handling
// ==========================================================================

async function handleExampleClick(type, target) {
  if (type !== state.currentTab) {
    switchTab(type);
  }

  const content = DEMO_PRESETS[type]?.[target];
  if (!content) return;

  if (type === 'url') {
    elements.urlInput.value = content;
  } else if (type === 'message') {
    elements.messageInput.value = content;
  } else if (type === 'screenshot') {
    await loadDemoScreenshot(target);
    return;
  }

  // Auto trigger scan
  handleScan();
}

// ==========================================================================
// Voice Call Handling (Gnani Prisma STT + Timbre TTS)
// ==========================================================================

const MAX_VOICE_SECONDS = 30;

const voice = {
  mediaRecorder: null,
  stream: null,
  chunks: [],
  timerInterval: null,
  startedAt: 0,
  language: 'en-IN',
  alertUrl: null
};

function initializeVoiceTab() {
  elements.recordBtn.addEventListener('click', () => {
    if (voice.mediaRecorder && voice.mediaRecorder.state !== 'inactive') {
      stopRecording();
    } else {
      startRecording();
    }
  });

  elements.voiceFileInput.addEventListener('change', (e) => {
    if (e.target.files.length > 0) {
      handleVoiceFile(e.target.files[0]);
      e.target.value = '';
    }
  });

  elements.voicePlayAlertBtn.addEventListener('click', () => playVoiceAlert());
}

async function startRecording() {
  if (API_BASE === null) {
    showToast('Voice mode needs the backend server (port 3001) running.', 'error');
    return;
  }
  try {
    voice.stream = await navigator.mediaDevices.getUserMedia({ audio: true });
  } catch (err) {
    showToast('Microphone access denied.', 'error');
    return;
  }

  voice.chunks = [];
  voice.mediaRecorder = new MediaRecorder(voice.stream);
  voice.mediaRecorder.ondataavailable = (e) => {
    if (e.data.size > 0) voice.chunks.push(e.data);
  };
  voice.mediaRecorder.onstop = async () => {
    voice.stream.getTracks().forEach((t) => t.stop());
    voice.stream = null;
    const blob = new Blob(voice.chunks, { type: voice.mediaRecorder.mimeType });
    await processVoiceAudio(blob);
  };

  voice.mediaRecorder.start();
  voice.startedAt = Date.now();
  elements.recordBtn.classList.add('recording');
  elements.recordLabel.textContent = 'Stop recording';
  setVoiceStatus('Listening... the call audio is being recorded (max 30s).');

  voice.timerInterval = setInterval(() => {
    const elapsed = (Date.now() - voice.startedAt) / 1000;
    elements.recordTimer.textContent = `0:${String(Math.min(30, Math.floor(elapsed))).padStart(2, '0')} / 0:30`;
    if (elapsed >= MAX_VOICE_SECONDS) stopRecording();
  }, 250);

  setTimeout(() => {
    if (voice.mediaRecorder && voice.mediaRecorder.state === 'recording') stopRecording();
  }, MAX_VOICE_SECONDS * 1000);
}

function stopRecording() {
  clearInterval(voice.timerInterval);
  voice.timerInterval = null;
  elements.recordBtn.classList.remove('recording');
  elements.recordLabel.textContent = 'Record scam call';
  elements.recordTimer.textContent = '0:00 / 0:30';
  if (voice.mediaRecorder && voice.mediaRecorder.state !== 'inactive') {
    voice.mediaRecorder.stop();
  }
}

async function handleVoiceFile(file) {
  if (API_BASE === null) {
    showToast('Voice mode needs the backend server (port 3001) running.', 'error');
    return;
  }
  setVoiceStatus(`Processing "${file.name}"...`);
  await processVoiceAudio(file);
}

async function processVoiceAudio(blob) {
  setVoiceStatus('Transcribing with Gnani Prisma v3.0...');
  try {
    const wav = await blobToWav16k(blob);
    const response = await fetch(`${API_BASE}/api/voice/transcribe`, {
      method: 'POST',
      headers: { 'Content-Type': 'audio/wav' },
      body: wav
    });
    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.error || 'Transcription failed.');
    }
    if (!data.transcript || !data.transcript.trim()) {
      setVoiceStatus('No speech detected in that audio.');
      elements.voiceTranscriptBox.classList.add('hidden');
      return;
    }
    voice.language = data.language || 'en-IN';
    elements.voiceTranscript.value = data.transcript;
    elements.voiceLangBadge.textContent = voice.language;
    elements.voiceTranscriptBox.classList.remove('hidden');
    setVoiceStatus(`Transcribed (${voice.language}). Hit Scan Now to check it for scam signals.`);
  } catch (err) {
    console.error('Voice transcription error:', err);
    setVoiceStatus(`Voice transcription failed: ${err.message}`);
    showToast(err.message, 'error');
  }
}

function setVoiceStatus(message) {
  elements.voiceStatus.textContent = message;
  elements.voiceStatus.classList.remove('hidden');
}

// Decode any browser-supported audio, downmix to mono, resample to 16 kHz,
// trim to 30 s (Prisma REST limit) and encode as 16-bit PCM WAV.
async function blobToWav16k(blob) {
  const Ctor = window.AudioContext || window.webkitAudioContext;
  const ctx = new Ctor();
  let decoded;
  try {
    decoded = await ctx.decodeAudioData(await blob.arrayBuffer());
  } finally {
    ctx.close();
  }

  const targetRate = 16000;
  const seconds = Math.min(decoded.duration, MAX_VOICE_SECONDS);
  const offline = new OfflineAudioContext(1, Math.ceil(seconds * targetRate), targetRate);
  const source = offline.createBufferSource();
  source.buffer = decoded;
  source.connect(offline.destination);
  source.start();
  const rendered = await offline.startRendering();
  return encodeWav16(rendered.getChannelData(0), targetRate);
}

function encodeWav16(samples, sampleRate) {
  const buffer = new ArrayBuffer(44 + samples.length * 2);
  const view = new DataView(buffer);

  function writeString(offset, str) {
    for (let i = 0; i < str.length; i++) view.setUint8(offset + i, str.charCodeAt(i));
  }

  writeString(0, 'RIFF');
  view.setUint32(4, 36 + samples.length * 2, true);
  writeString(8, 'WAVE');
  writeString(12, 'fmt ');
  view.setUint32(16, 16, true);
  view.setUint16(20, 1, true);
  view.setUint16(22, 1, true);
  view.setUint32(24, sampleRate, true);
  view.setUint32(28, sampleRate * 2, true);
  view.setUint32(32, 2, true);
  view.setUint16(34, 16, true);
  writeString(36, 'data');
  view.setUint32(40, samples.length * 2, true);

  let offset = 44;
  for (let i = 0; i < samples.length; i++, offset += 2) {
    const value = Math.max(-1, Math.min(1, samples[i]));
    view.setInt16(offset, value < 0 ? value * 0x8000 : value * 0x7fff, true);
  }
  return buffer;
}

function maybeSpeakVoiceAlert(result) {
  const dangerous = result.riskLevel === 'high' || result.riskLevel === 'critical';
  if (!dangerous || API_BASE === null) {
    elements.voicePlayAlertBtn.hidden = true;
    return;
  }
  speakScamAlert(result);
}

async function speakScamAlert(result) {
  const baseWarning = voice.language.startsWith('hi')
    ? 'सावधान! यह कॉल धोखाधड़ी जैसी लग रही है। अपना OTP, PIN या बैंक विवरण साझा न करें।'
    : 'Warning! This call looks like a scam. Do not share your OTP, PIN, or bank details.';
  try {
    const response = await fetch(`${API_BASE}/api/voice/alert`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        text: `${baseWarning} ${result.summary || ''}`.trim(),
        language: voice.language
      })
    });
    if (!response.ok) throw new Error('alert failed');
    const blob = await response.blob();
    if (voice.alertUrl) URL.revokeObjectURL(voice.alertUrl);
    voice.alertUrl = URL.createObjectURL(blob);
    elements.voicePlayAlertBtn.hidden = false;
    playVoiceAlert();
  } catch (err) {
    console.warn('Voice alert unavailable:', err);
  }
}

function playVoiceAlert() {
  if (!voice.alertUrl) return;
  const audio = new Audio(voice.alertUrl);
  audio.play().catch(() => {});
}

// ==========================================================================
// Screenshot Handling
// ==========================================================================

async function initializeOCRWorker() {
  if (state.ocrWorkerReady) return;
  
  try {
    elements.progressStatus.textContent = 'Loading OCR engine...';
    elements.progressDetail.textContent = 'Downloading language data on first use (~10MB)';
    elements.ocrProgress.classList.remove('hidden');
    elements.screenshotDropzone.classList.add('hidden');
    
    tesseractWorker = await Tesseract.createWorker('eng', 1, {
      logger: (m) => {
        if (m.status === 'recognizing text') {
          const pct = Math.round(m.progress * 100);
          elements.progressBar.style.width = `${pct}%`;
          elements.progressStatus.textContent = `Recognizing text... ${pct}%`;
          elements.progressDetail.textContent = 'Processing image locally in your browser';
        } else if (m.status === 'loading tesseract core') {
          elements.progressStatus.textContent = 'Loading OCR core...';
          elements.progressDetail.textContent = 'Initializing WebAssembly modules';
        } else if (m.status === 'initializing api') {
          elements.progressStatus.textContent = 'Initializing...';
        }
      }
    });
    
    state.ocrWorkerReady = true;
    elements.ocrProgress.classList.add('hidden');
    elements.screenshotDropzone.classList.remove('hidden');
  } catch (err) {
    console.error('Failed to initialize OCR worker:', err);
    showScreenshotError('Failed to load OCR engine. Please refresh and try again.');
  }
}

function handleScreenshotFile(file) {
  // Validate file type
  if (!file.type.startsWith('image/')) {
    showToast('Please select an image file.', 'error');
    return;
  }

  // Validate file size (max 10MB)
  if (file.size > 10 * 1024 * 1024) {
    showToast('Image too large. Maximum size is 10MB.', 'error');
    return;
  }

  state.screenshotFile = file;
  
  // Create image preview
  const url = URL.createObjectURL(file);
  state.screenshotImage = url;
  elements.previewImage.src = url;
  elements.imagePreview.classList.remove('hidden');
  elements.screenshotDropzone.classList.add('hidden');
  elements.screenshotExamples.style.display = 'none';
  elements.extractedContent.classList.add('hidden');
  elements.screenshotError.classList.add('hidden');
  
  // Process the image
  processScreenshot(url);
}

function clearScreenshot() {
  if (state.screenshotImage) {
    URL.revokeObjectURL(state.screenshotImage);
  }
  state.screenshotFile = null;
  state.screenshotImage = null;
  state.extractedText = '';
  state.extractedLinks = [];
  state.qrContent = '';
  
  elements.previewImage.src = '';
  elements.imagePreview.classList.add('hidden');
  elements.screenshotDropzone.classList.remove('hidden');
  elements.screenshotExamples.style.display = 'flex';
  elements.extractedContent.classList.add('hidden');
  elements.screenshotError.classList.add('hidden');
  elements.ocrProgress.classList.add('hidden');
  elements.screenshotFileInput.value = '';
}

async function processScreenshot(imageUrl) {
  if (!state.ocrWorkerReady) {
    await initializeOCRWorker();
  }
  
  if (!tesseractWorker) {
    showScreenshotError('OCR engine not ready. Please try again.');
    return;
  }

  elements.ocrProgress.classList.remove('hidden');
  elements.imagePreview.classList.add('hidden');
  elements.extractedContent.classList.add('hidden');
  elements.screenshotError.classList.add('hidden');
  
  elements.progressBar.style.width = '0%';
  elements.progressStatus.textContent = 'Starting OCR...';
  elements.progressDetail.textContent = 'Analyzing image locally — no data leaves your device';

  try {
    // Run OCR
    const { data: { text, confidence } } = await tesseractWorker.recognize(imageUrl);
    state.extractedText = text.trim();
    
    // Update progress for QR detection
    elements.progressStatus.textContent = 'Checking for QR codes...';
    elements.progressDetail.textContent = 'Scanning image for QR codes';
    elements.progressBar.style.width = '90%';
    
    // Run QR detection
    const qrData = await detectQRCode(imageUrl);
    state.qrContent = qrData || '';
    
    // Extract links from OCR text and QR content
    state.extractedLinks = extractLinksFromText(state.extractedText);
    if (state.qrContent) {
      const qrLinks = extractLinksFromText(state.qrContent);
      qrLinks.forEach(link => {
        if (!state.extractedLinks.some(l => l.url === link.url)) {
          state.extractedLinks.push({ ...link, source: 'qr' });
        }
      });
    }
    
    // Mark OCR-sourced links
    state.extractedLinks.forEach(link => {
      if (!link.source) link.source = 'ocr';
    });
    
    elements.progressBar.style.width = '100%';
    elements.progressStatus.textContent = 'Processing complete';
    elements.progressDetail.textContent = `Found ${state.extractedLinks.length} link(s)${state.qrContent ? ' and QR code' : ''}`;
    
    // Show results
    setTimeout(() => {
      displayExtractedContent();
    }, 500);
    
  } catch (err) {
    console.error('Screenshot processing error:', err);
    showScreenshotError('Failed to process image. The image may be too blurry, low contrast, or contain no readable text.');
  }
}

async function detectQRCode(imageUrl) {
  return new Promise((resolve) => {
    const img = new Image();
    img.crossOrigin = 'anonymous';
    img.onload = () => {
      const canvas = document.createElement('canvas');
      const ctx = canvas.getContext('2d');
      canvas.width = img.width;
      canvas.height = img.height;
      ctx.drawImage(img, 0, 0);
      
      const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
      const code = jsQR(imageData.data, imageData.width, imageData.height);
      
      if (code) {
        resolve(code.data);
      } else {
        resolve(null);
      }
    };
    img.onerror = () => resolve(null);
    img.src = imageUrl;
  });
}

function extractLinksFromText(text) {
  if (!text) return [];
  
  // Regex to match URLs (including those without protocol)
  const urlRegex = /(?:https?:\/\/|www\.)[^\s<>"{}|\\^`\[\]]+/gi;
  const matches = text.match(urlRegex) || [];
  
  // Also match bare domains with suspicious TLDs or common patterns
  const bareDomainRegex = /\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:com|net|org|io|co|app|dev|xyz|tk|ml|ga|cf|top|click|link|buzz|work)\b/gi;
  const bareMatches = text.match(bareDomainRegex) || [];
  
  // Normalize URLs for deduplication (remove protocol, trailing slashes, paths)
  function normalizeUrl(url) {
    let normalized = url.replace(/^https?:\/\//, '').replace(/^www\./, '');
    // Remove path/query/fragment for domain-level deduplication
    normalized = normalized.split('/')[0].split('?')[0].split('#')[0];
    return normalized.toLowerCase();
  }
  
  // Combine and deduplicate by normalized domain
  const seen = new Set();
  const allUrls = [...matches, ...bareMatches].filter(url => {
    const norm = normalizeUrl(url);
    if (seen.has(norm)) return false;
    seen.add(norm);
    return true;
  });
  
  return allUrls.map(url => ({
    url: url.startsWith('http') ? url : 'https://' + url,
    source: 'ocr'
  }));
}

function displayExtractedContent() {
  elements.ocrProgress.classList.add('hidden');
  elements.imagePreview.classList.remove('hidden');
  elements.extractedContent.classList.remove('hidden');
  
  // Set extracted text (user can edit)
  elements.extractedText.value = state.extractedText || '(No text detected — image may be blurry, low contrast, or text-free)';
  
  // Update state when user edits text
  elements.extractedText.oninput = () => {
    state.extractedText = elements.extractedText.value;
  };
  
  // Set OCR method badge
  elements.ocrMethodBadge.textContent = 'OCR';
  
  // Display links
  if (state.extractedLinks.length > 0) {
    elements.linksSection.style.display = 'block';
    elements.linkCountBadge.textContent = state.extractedLinks.length;
    renderLinksList();
  } else {
    elements.linksSection.style.display = 'none';
  }
  
  // Display QR content
  if (state.qrContent) {
    elements.qrSection.style.display = 'block';
    elements.qrContent.value = state.qrContent;
    elements.qrStatusBadge.textContent = 'Found';
  } else {
    elements.qrSection.style.display = 'none';
  }
}

function renderLinksList() {
  elements.linksList.innerHTML = '';
  
  state.extractedLinks.forEach((link, index) => {
    const div = document.createElement('div');
    div.className = 'link-item';
    div.innerHTML = `
      <span class="link-icon" aria-hidden="true">🔗</span>
      <input type="text" class="link-url-input" value="${escapeHTML(link.url)}" data-index="${index}" title="Edit URL if OCR misread it" aria-label="Extracted URL (editable)">
      <span class="link-source ${link.source}">${link.source.toUpperCase()}</span>
    `;
    elements.linksList.appendChild(div);
  });
  
  // Add input listeners to update state when user edits URLs
  elements.linksList.querySelectorAll('.link-url-input').forEach(input => {
    input.addEventListener('change', (e) => {
      const idx = parseInt(e.target.dataset.index, 10);
      if (state.extractedLinks[idx]) {
        state.extractedLinks[idx].url = e.target.value.trim();
      }
    });
  });
}

function copyExtractedText() {
  const currentText = elements.extractedText.value.trim();
  if (!currentText) {
    showToast('No text to copy.', 'info');
    return;
  }
  
  navigator.clipboard.writeText(currentText).then(() => {
    showToast('Extracted text copied to clipboard.', 'success');
    elements.copyTextBtn.textContent = '✓';
    setTimeout(() => { elements.copyTextBtn.textContent = '📋'; }, 2000);
  }).catch(() => {
    showToast('Failed to copy text.', 'error');
  });
}

async function handleScanExtracted() {
  // Read current edited text from textarea
  const editedText = elements.extractedText.value.trim();
  
  // Read current edited URLs from inputs
  const editedLinks = [];
  elements.linksList.querySelectorAll('.link-url-input').forEach((input, idx) => {
    const url = input.value.trim();
    if (url) {
      editedLinks.push({
        url: url.startsWith('http') ? url : 'https://' + url,
        source: state.extractedLinks[idx]?.source || 'ocr',
        originalIndex: idx
      });
    }
  });
  
  // Include QR content if present
  const qrContent = elements.qrContent.value.trim();
  
  if (!editedText && editedLinks.length === 0 && !qrContent) {
    showToast('No content to scan. Please upload an image with readable text or QR codes.', 'error');
    return;
  }
  
  // Build combined message for message analyzer: edited text + all links
  const messageContent = [
    editedText,
    ...editedLinks.map(l => l.url)
  ].filter(Boolean).join('\n\n');
  
  setScanningState(true);
  
  const startTime = performance.now();
  
  // Run message analyzer on combined content (local only)
  const messageResult = analyzeMessageDemo(messageContent);
  
  // Normalize URL for deduplication
  function normalizeUrl(url) {
    let normalized = url.replace(/^https?:\/\//, '').replace(/^www\./, '');
    normalized = normalized.split('/')[0].split('?')[0].split('#')[0];
    return normalized.toLowerCase();
  }

  // Run URL analyzer on each extracted link separately (local only)
  const urlResults = [];
  const seenUrls = new Set();
  
  for (const link of editedLinks) {
    const norm = normalizeUrl(link.url);
    if (seenUrls.has(norm)) continue;
    seenUrls.add(norm);
    const urlResult = analyzeUrlDemo(link.url);
    urlResults.push({
      url: link.url,
      source: link.source,
      result: urlResult
    });
  }
  
  // Also analyze QR content as a URL if it looks like one and isn't already analyzed
  if (qrContent && (qrContent.startsWith('http') || qrContent.includes('.'))) {
    const qrNorm = normalizeUrl(qrContent);
    if (!seenUrls.has(qrNorm)) {
      const qrUrlResult = analyzeUrlDemo(qrContent);
      urlResults.push({
        url: qrContent,
        source: 'qr',
        result: qrUrlResult
      });
    }
  }
  
  // Combine all flags with source attribution
  const allFlags = [];
  
  // Message-level flags (from analyzeMessageDemo)
  for (const flag of messageResult.flags) {
    // Skip the "Embedded Link" flag since we're analyzing links separately
    if (flag.name === 'Embedded Link') continue;
    // Skip "Unindexed / Standard Domain" from message analysis
    if (flag.name === 'Unindexed / Standard Domain') continue;
    allFlags.push({
      ...flag,
      source: 'message',
      sourceLabel: 'Message text'
    });
  }
  
  // Per-URL flags (from analyzeUrlDemo)
  for (const urlResult of urlResults) {
    for (const flag of urlResult.result.flags) {
      // Skip "Unindexed / Standard Domain" - not useful here
      if (flag.name === 'Unindexed / Standard Domain') continue;
      allFlags.push({
        ...flag,
        source: 'url',
        sourceLabel: `URL: ${truncateText(urlResult.url, 40)}`,
        urlSource: urlResult.source
      });
    }
  }
  
  // Calculate overall score: max of message score and all URL scores
  let maxScore = messageResult.score;
  for (const urlResult of urlResults) {
    maxScore = Math.max(maxScore, urlResult.result.score);
  }
  
  const { score, verdict, riskLevel } = getVerdictAndRisk(maxScore);
  
  // Build summary mentioning both message and URL findings
  let summary = '';
  const urlThreats = urlResults.filter(u => u.result.score >= 41);
  const msgRisk = messageResult.riskLevel;
  
  if (riskLevel === 'critical' || riskLevel === 'high') {
    if (urlThreats.length > 0) {
      summary = `High-risk content detected. The message text shows ${msgRisk} risk, and ${urlThreats.length} extracted link(s) scored ${urlThreats.map(u => u.result.score).join(', ')}/100.`;
    } else {
      summary = `High-risk indicators in the message text (${msgRisk}). No extracted links scored as high-risk independently.`;
    }
  } else if (riskLevel === 'medium') {
    summary = `Suspicious content detected. Message risk: ${msgRisk}. ${urlThreats.length > 0 ? `${urlThreats.length} link(s) flagged.` : 'No high-risk links found.'}`;
  } else {
    summary = `Content appears low-risk. Message: ${msgRisk}. ${editedLinks.length > 0 ? `${editedLinks.length} link(s) analyzed, none flagged.` : 'No links extracted.'}`;
  }
  
  // Build tips combining message and URL tips
  const allTips = [...new Set([
    ...messageResult.tips,
    ...urlResults.flatMap(u => u.result.tips)
  ])];
  
  const latency = Math.round(performance.now() - startTime);
  const remainingTime = Math.max(0, 700 - latency);
  await new Promise(resolve => setTimeout(resolve, remainingTime));
  
  setScanningState(false);
  
  const normalizedResult = {
    score,
    verdict,
    riskLevel,
    flags: allFlags,
    summary,
    tips: allTips.slice(0, 6), // limit tips
    mode: 'demo',
    confidence: formatConfidence(allFlags),
    latency
  };
  
  state.currentResult = normalizedResult;
  
  // Render results with screenshot indicator
  const linkCount = editedLinks.length + (qrContent ? 1 : 0);
  renderResults('screenshot', `Screenshot (${linkCount} link${linkCount !== 1 ? 's' : ''}${qrContent ? ', QR' : ''})`, normalizedResult);
  
  // Add to history
  addToHistory({
    id: Date.now(),
    type: 'screenshot',
    content: `Screenshot: ${editedText.substring(0, 50)}...`,
    result: normalizedResult,
    timestamp: new Date().toISOString()
  });
  
  setTimeout(() => {
    elements.resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }, 100);
}

function showScreenshotError(message) {
  elements.ocrProgress.classList.add('hidden');
  elements.imagePreview.classList.add('hidden');
  elements.extractedContent.classList.add('hidden');
  elements.screenshotError.classList.remove('hidden');
  elements.errorMessage.textContent = message;
}

async function loadDemoScreenshot(type) {
  // Create demo screenshots using canvas
  const canvas = document.createElement('canvas');
  const ctx = canvas.getContext('2d');
  canvas.width = 600;
  canvas.height = 800;
  
  // Background
  ctx.fillStyle = '#ffffff';
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  
  ctx.fillStyle = '#1a1a2e';
  ctx.font = '24px Arial';
  ctx.textAlign = 'center';
  
  let lines = [];
  let qrCodeDataUrl = null;
  
  if (type === 'phishing') {
    lines = [
      'URGENT: Account Security Alert',
      '',
      'Dear Customer,',
      '',
      'Your PayPal account has been',
      'temporarily suspended due to',
      'suspicious activity detected.',
      '',
      'Click here to verify:',
      'https://paypa1-security.com/verify',
      '',
      'You have 24 hours to act or',
      'your account will be closed.',
      '',
      'Thank you,',
      'PayPal Security Team'
    ];
  } else if (type === 'qr') {
    // Generate a real QR code containing a suspicious typosquatting URL
    const qrUrl = 'https://micros0ft-verify.com/login?token=xyz';
    qrCodeDataUrl = await generateQRCodeDataURL(qrUrl, 300);
    
    lines = [
      'Scan QR Code to Verify Account',
      '',
      'Your Microsoft account needs',
      'immediate verification.',
      '',
      '', // QR code will be drawn here
      '(Contains: https://micros0ft-',
      'verify.com/login?token=xyz)',
      '',
      'Do not share this code.',
      'Expires in 15 minutes.'
    ];
  } else { // legit
    lines = [
      'Hey!',
      '',
      'Just confirming our meeting',
      'tomorrow at 2pm at the usual',
      'coffee shop. Let me know if',
      'you need to reschedule.',
      '',
      'Also sending you that article',
      'on ML we discussed:',
      'https://github.com/user/repo',
      '',
      'See you then!'
    ];
  }
  
  let y = 60;
  lines.forEach(line => {
    if (line === '' && qrCodeDataUrl && type === 'qr') {
      // Draw the real QR code
      const qrImg = new Image();
      qrImg.onload = () => {
        ctx.drawImage(qrImg, 150, y, 300, 300);
      };
      qrImg.src = qrCodeDataUrl;
      y += 320;
    } else {
      ctx.fillText(line, canvas.width / 2, y);
      y += 36;
    }
  });
  
  // For QR demo, we need to wait for QR image to load before creating blob
  if (type === 'qr' && qrCodeDataUrl) {
    const qrImg = new Image();
    qrImg.onload = () => {
      ctx.drawImage(qrImg, 150, 200, 300, 300); // y=200 is the QR position
      canvas.toBlob((blob) => {
        const file = new File([blob], 'demo-screenshot-qr.png', { type: 'image/png' });
        handleScreenshotFile(file);
      }, 'image/png');
    };
    qrImg.src = qrCodeDataUrl;
  } else {
    canvas.toBlob((blob) => {
      const file = new File([blob], 'demo-screenshot.png', { type: 'image/png' });
      handleScreenshotFile(file);
    }, 'image/png');
  }
}

// Minimal QR code generator for demo (returns data URL)
async function generateQRCodeDataURL(text, size = 300) {
  // Use the qrcode library to generate a real QR code
  return await QRCode.toDataURL(text, {
    width: size,
    margin: 2,
    color: {
      dark: '#000000',
      light: '#ffffff'
    },
    errorCorrectionLevel: 'M'
  });
}

// ==========================================================================
// Scanning & API Handling
// ==========================================================================

async function handleScan() {
  if (state.isScanning) return;

  const isVoice = state.currentTab === 'voice';
  const inputEl = isVoice
    ? elements.voiceTranscript
    : state.currentTab === 'url' ? elements.urlInput : elements.messageInput;
  const content = inputEl.value.trim();

  // Validate Input
  if (!content) {
    inputEl.classList.add('shake-error');
    inputEl.focus();
    showToast(isVoice ? 'Record or upload a call first.' : 'Please enter a URL or message to scan.', 'error');
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

  if (API_BASE === null) {
    // Static deployment: run the local engine with no network round-trip.
    result = generateFallbackResult(isVoice ? 'message' : state.currentTab, processedContent);
  } else {
    try {
      const response = await fetch(`${API_BASE}/api/analyze`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          type: isVoice ? 'message' : state.currentTab,
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
      result = generateFallbackResult(isVoice ? 'message' : state.currentTab, processedContent);
      if (import.meta.env.DEV) {
        showToast('Backend offline (port 3001) — using local heuristic engine.', 'info');
      }
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

  const scanType = isVoice ? 'message' : state.currentTab;

  // Render & Animate Results
  renderResults(scanType, processedContent, normalizedResult);

  // Add to History
  addToHistory({
    id: Date.now(),
    type: scanType,
    content: processedContent,
    result: normalizedResult,
    timestamp: new Date().toISOString()
  });

  // Voice mode: speak a warning when the call looks dangerous
  if (isVoice) {
    maybeSpeakVoiceAlert(normalizedResult);
  }

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
    'Checking URL structure and lookalike patterns...',
    'Looking for suspicious host and path signals...',
    'Checking message wording for pressure tactics...',
    'Combining the evidence found in this scan...',
    'Preparing your risk summary...'
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
  const verdict = getScoreVerdict(score);
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
  const result = type === 'url' ? analyzeUrlDemo(content) : analyzeMessageDemo(content);
  return { ...result, mode: 'demo', latency: 280 };
}

// ==========================================================================
// Rendering Results
// ==========================================================================

function renderResults(type, content, result) {
  elements.resultsSection.style.display = 'flex';

  // Target Preview & Badge
  let typeBadgeText = '🔗 URL';
  if (type === 'message') typeBadgeText = '📧 Message';
  else if (type === 'screenshot') typeBadgeText = '📷 Screenshot';
  elements.resultTypeBadge.textContent = typeBadgeText;
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
        <h3>No Known Warning Signals</h3>
        <p>This local scan found no matching warning patterns. It does not visit the site or check live threat lists, so a low score cannot guarantee a link is safe.</p>
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

    // Source attribution badge
    let sourceHtml = '';
    if (flag.sourceLabel) {
      const sourceClass = flag.source === 'message' ? 'source-message' : 
                          flag.source === 'url' ? 'source-url' : 'source-other';
      sourceHtml = `<span class="flag-source ${sourceClass}">${escapeHTML(flag.sourceLabel)}</span>`;
    }

    card.innerHTML = `
      <div class="flag-top-row">
        <div class="flag-title-group">
          <span class="flag-icon" aria-hidden="true">${flag.icon || '⚠️'}</span>
          <span class="flag-name">${escapeHTML(flag.name)}</span>
        </div>
        <span class="severity-badge ${sevClass}">${escapeHTML(flag.severity)}</span>
      </div>
      ${sourceHtml ? `<div class="flag-source-row">${sourceHtml}</div>` : ''}
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

    let typeIcon = '🔗';
    if (item.type === 'message') typeIcon = '📧';
    else if (item.type === 'screenshot') typeIcon = '📷';
    
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
      } else if (item.type === 'message') {
        elements.messageInput.value = item.content;
      }
      // For screenshot, we can't easily restore the image, so just show the result
      // The user would need to re-upload the image

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
