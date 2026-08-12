'use strict';

const assert = require('assert');
const crypto = require('crypto');
const http = require('http');
const { Wallet } = require('ethers');

const PORT = 31991;
const ORIGIN = 'https://lively-fuwz.netlify.app';
const BASE = `http://127.0.0.1:${PORT}`;

process.env.PORT = String(PORT);
process.env.HOST = '127.0.0.1';
process.env.APP_ORIGIN = ORIGIN;
process.env.SESSION_SECRET = crypto.randomBytes(48).toString('base64url');
require('../server.js');

async function waitForServer() {
  for (let attempt = 0; attempt < 30; attempt += 1) {
    try {
      const response = await fetch(`${BASE}/api/status`);
      if (response.ok) return;
    } catch {}
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error('server did not start');
}

async function json(path, options = {}) {
  const response = await fetch(`${BASE}${path}`, options);
  return { response, data: await response.json() };
}

async function run() {
  await waitForServer();

  const status = await json('/api/status');
  assert.equal(status.response.status, 200);
  assert.equal(status.data.ok, true);

  const rejected = await json('/api/auth/challenge', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Origin: 'https://evil.example' },
    body: JSON.stringify({ address: Wallet.createRandom().address, chainId: 137, mode: 'login' })
  });
  assert.equal(rejected.response.status, 403);

  const wallet = Wallet.createRandom();
  const challenge = await json('/api/auth/challenge', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Origin: ORIGIN, 'X-Forwarded-For': '203.0.113.9' },
    body: JSON.stringify({ address: wallet.address, chainId: 137, mode: 'register' })
  });
  assert.equal(challenge.response.status, 200);
  assert.ok(challenge.data.message.includes('lively-fuwz.netlify.app wants you to sign in'));

  const signature = await wallet.signMessage(challenge.data.message);
  const verified = await json('/api/auth/verify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Origin: ORIGIN, 'X-Forwarded-For': '203.0.113.9' },
    body: JSON.stringify({ challengeId: challenge.data.challengeId, signature })
  });
  assert.equal(verified.response.status, 200);
  assert.equal(verified.data.user.address, wallet.address);
  const cookie = verified.response.headers.get('set-cookie');
  assert.ok(cookie && cookie.includes('HttpOnly') && cookie.includes('Secure'));

  const session = await json('/api/auth/session', { headers: { Cookie: cookie } });
  assert.equal(session.data.authenticated, true);
  assert.equal(session.data.user.address, wallet.address);

  const replay = await json('/api/auth/verify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Origin: ORIGIN, 'X-Forwarded-For': '203.0.113.9' },
    body: JSON.stringify({ challengeId: challenge.data.challengeId, signature })
  });
  assert.equal(replay.response.status, 400);

  const missingKey = await json('/api/coingecko?path=/api/v3/ping', { headers: { Origin: ORIGIN } });
  assert.equal(missingKey.response.status, 503);

  console.log('SELF_TEST=PASS');
}

run().then(() => process.exit(0)).catch((error) => {
  console.error(error);
  process.exit(1);
});
