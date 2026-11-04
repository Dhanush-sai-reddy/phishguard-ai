import { chromium } from 'playwright';

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
page.on('pageerror', (e) => console.log('PAGE ERROR:', e.message));

await page.goto('http://localhost:5173');
await page.waitForSelector('#tabVoice');
await page.click('#tabVoice');
await page.waitForSelector('#voiceInputSection.active');
console.log('voice tab active:', await page.isVisible('#recordBtn'));

const wav = process.argv[2] || '/tmp/pg_alert.wav';
await page.setInputFiles('#voiceFileInput', wav);
await page.waitForFunction(() => document.getElementById('voiceTranscript').value.trim().length > 0, { timeout: 20000 });
console.log('transcript:', await page.inputValue('#voiceTranscript'));
console.log('language badge:', await page.textContent('#voiceLangBadge'));

await page.click('#scanBtn');
await page.waitForSelector('#resultsSection:not([style*="display: none"])', { timeout: 15000 });
await page.waitForTimeout(1500);
const verdict = await page.textContent('#gaugeVerdict');
console.log('verdict:', verdict.trim());

await page.screenshot({ path: 'tests/voice-tab.png', fullPage: false });
console.log('screenshot: tests/voice-tab.png');
await browser.close();
