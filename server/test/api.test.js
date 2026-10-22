import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const PORT = 3999;
const BASE = `http://127.0.0.1:${PORT}`;
const root = dirname(dirname(fileURLToPath(import.meta.url)));
let child;

async function waitForServer(attempts = 40) {
  for (let i = 0; i < attempts; i += 1) {
    try {
      const res = await fetch(`${BASE}/api/health`);
      if (res.ok) return;
    } catch {
      // not up yet
    }
    await new Promise((r) => setTimeout(r, 150));
  }
  throw new Error('server did not start');
}

before(async () => {
  child = spawn(process.execPath, ['index.js'], {
    cwd: root,
    env: { ...process.env, PORT: String(PORT), OPENAI_API_KEY: '' },
    stdio: 'ignore',
  });
  await waitForServer();
});

after(() => {
  child?.kill();
});

test('health reports demo mode without a key', async () => {
  const res = await fetch(`${BASE}/api/health`);
  const body = await res.json();
  assert.equal(res.status, 200);
  assert.equal(body.status, 'ok');
  assert.equal(body.mode, 'demo');
});

test('phishing URL scores critical and explains why', async () => {
  const res = await fetch(`${BASE}/api/analyze`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      type: 'url',
      content: 'https://paypa1-secure.com/verify-account?id=8372',
    }),
  });
  const body = await res.json();
  assert.equal(res.status, 200);
  assert.ok(body.score >= 81, `expected critical score, got ${body.score}`);
  assert.equal(body.verdict, 'Critical Threat');
  assert.ok(body.flags.length >= 2);
  assert.ok(body.tips.length >= 1);
});

test('scoring is deterministic for the same input', async () => {
  const payload = {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ type: 'message', content: 'URGENT: verify your password now' }),
  };
  const a = await (await fetch(`${BASE}/api/analyze`, payload)).json();
  const b = await (await fetch(`${BASE}/api/analyze`, payload)).json();
  assert.equal(a.score, b.score);
  assert.equal(a.verdict, b.verdict);
});

test('trusted domain stays low risk', async () => {
  const res = await fetch(`${BASE}/api/analyze`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ type: 'url', content: 'https://github.com/Dhanush-sai-reddy/phishguard-ai' }),
  });
  const body = await res.json();
  assert.ok(body.score <= 20, `expected safe score, got ${body.score}`);
});

test('rejects malformed requests', async () => {
  const missingType = await fetch(`${BASE}/api/analyze`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ content: 'hello' }),
  });
  assert.equal(missingType.status, 400);

  const emptyContent = await fetch(`${BASE}/api/analyze`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ type: 'url', content: '   ' }),
  });
  assert.equal(emptyContent.status, 400);
});
