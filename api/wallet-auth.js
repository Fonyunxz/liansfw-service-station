'use strict';

const crypto = require('crypto');
const { getAddress, isAddress, verifyMessage } = require('ethers');

const COOKIE_NAME = 'onchain_session';
const CHALLENGE_TTL_MS = 5 * 60 * 1000;
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const MAX_BODY_BYTES = 16 * 1024;

function createWalletAuth(options = {}) {
  const sessionSecret = String(options.sessionSecret || process.env.SESSION_SECRET || '');
  const configuredOrigin = normalizeOrigin(options.appOrigin || process.env.APP_ORIGIN || '');
  const rateBuckets = new Map();
  const usedChallenges = new Map();

  if (sessionSecret.length < 32) {
    throw new Error('SESSION_SECRET 必须至少包含 32 个字符');
  }

  function sendJson(res, status, data) {
    const body = JSON.stringify(data);
    res.writeHead(status, {
      'Content-Type': 'application/json; charset=utf-8',
      'Content-Length': Buffer.byteLength(body),
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff'
    });
    res.end(body);
  }

  function clientIp(req) {
    return String(
      req.headers['cf-connecting-ip'] ||
      req.headers['x-nf-client-connection-ip'] ||
      (req.headers['x-forwarded-for'] && String(req.headers['x-forwarded-for']).split(',')[0].trim()) ||
      req.headers['x-real-ip'] ||
      (req.socket && req.socket.remoteAddress) ||
      'unknown'
    );
  }

  function allowRequest(key, limit, windowMs) {
    const now = Date.now();
    const recent = (rateBuckets.get(key) || []).filter((time) => now - time < windowMs);
    if (recent.length >= limit) {
      rateBuckets.set(key, recent);
      return false;
    }
    recent.push(now);
    rateBuckets.set(key, recent);
    return true;
  }

  function pruneExpired() {
    const now = Date.now();
    for (const [id, expiresAt] of usedChallenges) {
      if (expiresAt <= now) usedChallenges.delete(id);
    }
    for (const [key, times] of rateBuckets) {
      const recent = times.filter((time) => now - time < 10 * 60 * 1000);
      if (recent.length) rateBuckets.set(key, recent);
      else rateBuckets.delete(key);
    }
  }

  function requestOrigin(req) {
    if (configuredOrigin) {
      const url = new URL(configuredOrigin);
      return { domain: url.host, origin: url.origin };
    }
    const forwardedProto = String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim();
    const protocol = forwardedProto || (req.socket && req.socket.encrypted ? 'https' : 'http');
    const rawHost = String(req.headers.host || '127.0.0.1').trim();
    const host = /^[A-Za-z0-9.:[\]-]+$/.test(rawHost) ? rawHost : '127.0.0.1';
    return { domain: host, origin: `${protocol}://${host}` };
  }

  function validRequestOrigin(req) {
    const value = req.headers.origin || req.headers.referer;
    if (!value) return false;
    try {
      return new URL(String(value)).origin === requestOrigin(req).origin;
    } catch {
      return false;
    }
  }

  function signPayload(payload) {
    const encoded = Buffer.from(JSON.stringify(payload)).toString('base64url');
    const signature = crypto.createHmac('sha256', sessionSecret).update(encoded).digest('base64url');
    return `${encoded}.${signature}`;
  }

  function verifyPayload(token) {
    const [encoded, supplied] = String(token || '').split('.');
    if (!encoded || !supplied) return null;
    const expected = crypto.createHmac('sha256', sessionSecret).update(encoded).digest();
    let suppliedBuffer;
    try {
      suppliedBuffer = Buffer.from(supplied, 'base64url');
    } catch {
      return null;
    }
    if (expected.length !== suppliedBuffer.length || !crypto.timingSafeEqual(expected, suppliedBuffer)) return null;
    try {
      const payload = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));
      return payload && typeof payload === 'object' ? payload : null;
    } catch {
      return null;
    }
  }

  async function readJson(req) {
    return await new Promise((resolve, reject) => {
      let body = '';
      let tooLarge = false;
      req.setEncoding('utf8');
      req.on('data', (chunk) => {
        if (tooLarge) return;
        body += chunk;
        if (Buffer.byteLength(body) > MAX_BODY_BYTES) {
          tooLarge = true;
          reject(new Error('REQUEST_BODY_TOO_LARGE'));
        }
      });
      req.on('end', () => {
        if (tooLarge) return;
        try {
          resolve(body ? JSON.parse(body) : {});
        } catch {
          reject(new Error('INVALID_JSON'));
        }
      });
      req.on('error', reject);
    });
  }

  function parseCookies(req) {
    const result = {};
    String(req.headers.cookie || '').split(';').forEach((part) => {
      const index = part.indexOf('=');
      if (index < 0) return;
      const key = part.slice(0, index).trim();
      const value = part.slice(index + 1).trim();
      if (key) result[key] = value;
    });
    return result;
  }

  function sessionForRequest(req) {
    const payload = verifyPayload(parseCookies(req)[COOKIE_NAME]);
    if (!payload || payload.type !== 'session' || !isAddress(payload.address)) return null;
    if (!Number.isFinite(payload.expiresAt) || payload.expiresAt <= Date.now()) return null;
    return payload;
  }

  function publicUser(payload) {
    return {
      address: getAddress(payload.address),
      createdAt: payload.createdAt,
      lastLoginAt: payload.lastLoginAt
    };
  }

  function setSessionCookie(req, res, token) {
    const secure = requestOrigin(req).origin.startsWith('https://');
    const parts = [
      `${COOKIE_NAME}=${token}`,
      'Path=/',
      'HttpOnly',
      'SameSite=Lax',
      `Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}`
    ];
    if (secure) parts.push('Secure');
    res.setHeader('Set-Cookie', parts.join('; '));
  }

  function clearSessionCookie(req, res) {
    const secure = requestOrigin(req).origin.startsWith('https://');
    const parts = [`${COOKIE_NAME}=`, 'Path=/', 'HttpOnly', 'SameSite=Lax', 'Max-Age=0'];
    if (secure) parts.push('Secure');
    res.setHeader('Set-Cookie', parts.join('; '));
  }

  function challengeMessage(payload) {
    const { domain, origin } = requestOrigin(payload.req);
    const statement = payload.mode === 'register'
      ? '注册并登录链上服务站。此操作不会发起链上交易，也不会消耗 Gas。'
      : '登录链上服务站。此操作不会发起链上交易，也不会消耗 Gas。';
    return [
      `${domain} wants you to sign in with your Ethereum account:`,
      payload.address,
      '',
      statement,
      '',
      `URI: ${origin}`,
      'Version: 1',
      `Chain ID: ${payload.chainId}`,
      `Nonce: ${payload.nonce}`,
      `Issued At: ${new Date(payload.issuedAt).toISOString()}`,
      `Expiration Time: ${new Date(payload.expiresAt).toISOString()}`
    ].join('\n');
  }

  async function createChallenge(req, res) {
    if (!allowRequest(`challenge:${clientIp(req)}`, 12, 60 * 1000)) {
      return sendJson(res, 429, { ok: false, code: 'RATE_LIMITED', error: '请求过于频繁，请稍后再试' });
    }
    const body = await readJson(req);
    const rawAddress = String(body.address || '');
    const mode = body.mode === 'register' ? 'register' : body.mode === 'login' ? 'login' : '';
    const chainId = Number(body.chainId);
    if (!isAddress(rawAddress) || !mode || !Number.isSafeInteger(chainId) || chainId <= 0) {
      return sendJson(res, 400, { ok: false, code: 'INVALID_REQUEST', error: '钱包地址、网络或操作类型无效' });
    }

    const now = Date.now();
    const payload = {
      type: 'challenge',
      address: getAddress(rawAddress),
      chainId,
      mode,
      nonce: crypto.randomBytes(16).toString('hex'),
      issuedAt: now,
      expiresAt: now + CHALLENGE_TTL_MS
    };
    const message = challengeMessage({ ...payload, req });
    const challengeId = signPayload({ ...payload, message });
    return sendJson(res, 200, {
      ok: true,
      challengeId,
      message,
      expiresAt: new Date(payload.expiresAt).toISOString()
    });
  }

  async function verifyChallenge(req, res) {
    if (!allowRequest(`verify:${clientIp(req)}`, 20, 60 * 1000)) {
      return sendJson(res, 429, { ok: false, code: 'RATE_LIMITED', error: '验证过于频繁，请稍后再试' });
    }
    const body = await readJson(req);
    const challengeId = String(body.challengeId || '');
    const signature = String(body.signature || '');
    const challenge = verifyPayload(challengeId);
    const challengeHash = crypto.createHash('sha256').update(challengeId).digest('hex');
    if (!challenge || challenge.type !== 'challenge' || challenge.expiresAt <= Date.now() || usedChallenges.has(challengeHash)) {
      return sendJson(res, 400, { ok: false, code: 'CHALLENGE_INVALID', error: '登录请求已失效，请重新连接钱包' });
    }
    if (challengeMessage({ ...challenge, req }) !== challenge.message) {
      return sendJson(res, 400, { ok: false, code: 'CHALLENGE_INVALID', error: '登录请求域名无效' });
    }

    let recovered;
    try {
      recovered = getAddress(verifyMessage(challenge.message, signature));
    } catch {
      return sendJson(res, 401, { ok: false, code: 'SIGNATURE_INVALID', error: '钱包签名验证失败' });
    }
    if (recovered.toLowerCase() !== String(challenge.address).toLowerCase()) {
      return sendJson(res, 401, { ok: false, code: 'ADDRESS_MISMATCH', error: '签名钱包与连接钱包不一致' });
    }

    usedChallenges.set(challengeHash, challenge.expiresAt);
    const now = new Date().toISOString();
    const session = {
      type: 'session',
      address: recovered,
      createdAt: now,
      lastLoginAt: now,
      expiresAt: Date.now() + SESSION_TTL_MS,
      nonce: crypto.randomBytes(16).toString('hex')
    };
    setSessionCookie(req, res, signPayload(session));
    return sendJson(res, 200, {
      ok: true,
      isNew: challenge.mode === 'register',
      user: publicUser(session)
    });
  }

  function getSession(req, res) {
    const session = sessionForRequest(req);
    return sendJson(res, 200, session
      ? { ok: true, authenticated: true, user: publicUser(session) }
      : { ok: true, authenticated: false, user: null });
  }

  async function handle(requestUrl, req, res) {
    pruneExpired();
    const pathname = requestUrl.pathname;
    if (pathname === '/api/auth/session') {
      if (req.method !== 'GET') return sendJson(res, 405, { ok: false, error: 'Method Not Allowed' });
      return getSession(req, res);
    }
    if (req.method !== 'POST') return sendJson(res, 405, { ok: false, error: 'Method Not Allowed' });
    if (!validRequestOrigin(req)) {
      return sendJson(res, 403, { ok: false, code: 'ORIGIN_REJECTED', error: '请求来源无效' });
    }
    if (pathname === '/api/auth/challenge') return await createChallenge(req, res);
    if (pathname === '/api/auth/verify') return await verifyChallenge(req, res);
    if (pathname === '/api/auth/logout') {
      clearSessionCookie(req, res);
      return sendJson(res, 200, { ok: true });
    }
    return sendJson(res, 404, { ok: false, error: 'Not Found' });
  }

  return { handle };
}

function normalizeOrigin(value) {
  if (!value) return '';
  try {
    const url = new URL(String(value));
    return ['http:', 'https:'].includes(url.protocol) ? url.origin : '';
  } catch {
    return '';
  }
}

module.exports = { createWalletAuth };
