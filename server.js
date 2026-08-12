'use strict';

const http = require('http');
const { createWalletAuth } = require('./api/wallet-auth.js');
const chatHandler = require('./api/chat.js');

const PORT = Number(process.env.PORT) || 3000;
const HOST = process.env.HOST || '0.0.0.0';
const MAX_BODY_BYTES = 1024 * 1024;
const MAX_UPSTREAM_BYTES = 8 * 1024 * 1024;
const PROVIDER_TIMEOUT_MS = 15000;
const APP_ORIGIN = normalizeOrigin(process.env.APP_ORIGIN || 'http://127.0.0.1:3000');
const requestBuckets = new Map();

const walletAuth = createWalletAuth({
  appOrigin: APP_ORIGIN,
  sessionSecret: process.env.SESSION_SECRET
});

function normalizeOrigin(value) {
  try {
    const url = new URL(String(value));
    return ['http:', 'https:'].includes(url.protocol) ? url.origin : '';
  } catch {
    return '';
  }
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
  const row = requestBuckets.get(key) || { count: 0, startedAt: now };
  if (now - row.startedAt >= windowMs) {
    row.count = 0;
    row.startedAt = now;
  }
  row.count += 1;
  requestBuckets.set(key, row);
  if (requestBuckets.size > 5000) {
    for (const [bucketKey, bucket] of requestBuckets) {
      if (now - bucket.startedAt >= windowMs) requestBuckets.delete(bucketKey);
    }
  }
  return row.count <= limit;
}

function isAllowedWebsiteRequest(req) {
  const value = req.headers.origin || req.headers.referer;
  if (!value) return true;
  try {
    return new URL(String(value)).origin === APP_ORIGIN;
  } catch {
    return false;
  }
}

function getSecret(...names) {
  for (const name of names) {
    if (process.env[name]) return process.env[name];
  }
  return '';
}

function providerStatus() {
  return {
    coingecko: Boolean(getSecret('COINGECKO_API_KEY')),
    deepseek: Boolean(getSecret('DEEPSEEK_API_KEY')),
    etherscan: Boolean(getSecret('ETHERSCAN_API_KEY', 'ETHERSCAN_V2_API_KEY')),
    debank: Boolean(getSecret('DEBANK_API_KEY')),
    ankr: Boolean(getSecret('ANKR_API_KEY')),
    goldrush: Boolean(getSecret('GOLDRUSH_API_KEY', 'COVALENT_API_KEY')),
    alchemy: Boolean(getSecret('ALCHEMY_API_KEY'))
  };
}

function sendJson(res, status, data, extraHeaders = {}) {
  const body = JSON.stringify(data);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    ...extraHeaders
  });
  res.end(body);
}

function sendMethodNotAllowed(res) {
  return sendJson(res, 405, { ok: false, error: 'Method Not Allowed' });
}

function sendMissingKey(res, provider) {
  return sendJson(res, 503, { ok: false, error: `${provider} API Key 未配置` });
}

function readBody(req, maxBytes = MAX_BODY_BYTES) {
  return new Promise((resolve, reject) => {
    let body = '';
    let tooLarge = false;
    req.setEncoding('utf8');
    req.on('data', (chunk) => {
      if (tooLarge) return;
      body += chunk;
      if (Buffer.byteLength(body) > maxBytes) {
        tooLarge = true;
        reject(new Error('REQUEST_BODY_TOO_LARGE'));
      }
    });
    req.on('end', () => {
      if (!tooLarge) resolve(body);
    });
    req.on('error', reject);
  });
}

function validatedProviderPath(rawPath) {
  const value = String(rawPath || '');
  if (!value.startsWith('/') || value.includes('..') || !/^\/[A-Za-z0-9._~!$&'()*+,;=:@%/\-]+$/.test(value)) {
    return null;
  }
  return value;
}

function copySearchParams(source, target, omitted = []) {
  const blocked = new Set(omitted.map((name) => name.toLowerCase()));
  source.forEach((value, key) => {
    if (!blocked.has(key.toLowerCase())) target.append(key, value);
  });
}

async function providerFetch(target, options = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), PROVIDER_TIMEOUT_MS);
  try {
    return await fetch(target, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

async function relayProviderResponse(upstream, res) {
  const contentLength = Number(upstream.headers.get('content-length') || 0);
  if (contentLength > MAX_UPSTREAM_BYTES) {
    return sendJson(res, 502, { ok: false, error: '上游响应过大' });
  }
  const data = Buffer.from(await upstream.arrayBuffer());
  if (data.length > MAX_UPSTREAM_BYTES) {
    return sendJson(res, 502, { ok: false, error: '上游响应过大' });
  }
  res.writeHead(upstream.status, {
    'Content-Type': upstream.headers.get('content-type') || 'application/json; charset=utf-8',
    'Content-Length': data.length,
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff'
  });
  res.end(data);
}

async function handleEtherscan(requestUrl, req, res) {
  if (req.method !== 'GET') return sendMethodNotAllowed(res);
  const apiKey = getSecret('ETHERSCAN_API_KEY', 'ETHERSCAN_V2_API_KEY');
  if (!apiKey) return sendMissingKey(res, 'Etherscan');
  const target = new URL('https://api.etherscan.io/v2/api');
  copySearchParams(requestUrl.searchParams, target.searchParams, ['apikey']);
  if (!target.searchParams.has('chainid')) target.searchParams.set('chainid', '1');
  target.searchParams.set('apikey', apiKey);
  return relayProviderResponse(await providerFetch(target), res);
}

async function handleCoinGecko(requestUrl, req, res) {
  if (req.method !== 'GET') return sendMethodNotAllowed(res);
  const apiKey = getSecret('COINGECKO_API_KEY');
  if (!apiKey) return sendMissingKey(res, 'CoinGecko');
  const providerPath = validatedProviderPath(requestUrl.searchParams.get('path'));
  if (!providerPath || !providerPath.startsWith('/api/v3/')) {
    return sendJson(res, 400, { ok: false, error: 'CoinGecko path 无效' });
  }
  const isDemoKey = apiKey.startsWith('CG-');
  const target = new URL(providerPath, isDemoKey ? 'https://api.coingecko.com' : 'https://pro-api.coingecko.com');
  copySearchParams(requestUrl.searchParams, target.searchParams, ['path', 'x_cg_demo_api_key', 'x_cg_pro_api_key']);
  const headers = isDemoKey ? { 'x-cg-demo-api-key': apiKey } : { 'x-cg-pro-api-key': apiKey };
  return relayProviderResponse(await providerFetch(target, { headers }), res);
}

async function handleGoldRush(requestUrl, req, res) {
  if (req.method !== 'GET') return sendMethodNotAllowed(res);
  const apiKey = getSecret('GOLDRUSH_API_KEY', 'COVALENT_API_KEY');
  if (!apiKey) return sendMissingKey(res, 'GoldRush');
  const providerPath = validatedProviderPath(requestUrl.searchParams.get('path'));
  if (!providerPath || !providerPath.startsWith('/v1/')) {
    return sendJson(res, 400, { ok: false, error: 'GoldRush path 无效' });
  }
  const target = new URL(providerPath, 'https://api.covalenthq.com');
  copySearchParams(requestUrl.searchParams, target.searchParams, ['path', 'key']);
  // GoldRush accepts Basic auth; legacy Covalent endpoints also accept the
  // key query parameter. Supplying both keeps old site tools compatible.
  target.searchParams.set('key', apiKey);
  const authorization = Buffer.from(`${apiKey}:`).toString('base64');
  return relayProviderResponse(await providerFetch(target, { headers: { Authorization: `Basic ${authorization}` } }), res);
}

async function handleDeBank(requestUrl, req, res) {
  if (req.method !== 'GET') return sendMethodNotAllowed(res);
  const apiKey = getSecret('DEBANK_API_KEY');
  if (!apiKey) return sendMissingKey(res, 'DeBank');
  const providerPath = validatedProviderPath(requestUrl.searchParams.get('path'));
  if (!providerPath || !providerPath.startsWith('/v1/')) {
    return sendJson(res, 400, { ok: false, error: 'DeBank path 无效' });
  }
  const target = new URL(providerPath, 'https://pro-openapi.debank.com');
  copySearchParams(requestUrl.searchParams, target.searchParams, ['path', 'accesskey']);
  return relayProviderResponse(await providerFetch(target, { headers: { AccessKey: apiKey } }), res);
}

async function handleAnkr(requestUrl, req, res) {
  if (req.method !== 'POST') return sendMethodNotAllowed(res);
  const apiKey = getSecret('ANKR_API_KEY');
  if (!apiKey) return sendMissingKey(res, 'Ankr');
  const chain = String(requestUrl.searchParams.get('chain') || 'multichain').toLowerCase();
  if (!new Set(['multichain', 'eth', 'polygon', 'bsc', 'arbitrum', 'optimism']).has(chain)) {
    return sendJson(res, 400, { ok: false, error: 'Ankr chain 无效' });
  }
  const body = await readBody(req, 256 * 1024);
  return relayProviderResponse(await providerFetch(`https://rpc.ankr.com/${chain}/${apiKey}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body
  }), res);
}

async function handleRpc(requestUrl, req, res) {
  if (req.method !== 'POST') return sendMethodNotAllowed(res);
  const alchemyKey = getSecret('ALCHEMY_API_KEY');
  const ankrKey = getSecret('ANKR_API_KEY');
  if (String(requestUrl.searchParams.get('chain') || 'polygon').toLowerCase() !== 'polygon') {
    return sendJson(res, 400, { ok: false, error: 'RPC chain 无效' });
  }
  if (!alchemyKey && !ankrKey) return sendMissingKey(res, 'RPC');
  const body = await readBody(req, 256 * 1024);
  const target = alchemyKey
    ? `https://polygon-mainnet.g.alchemy.com/v2/${alchemyKey}`
    : `https://rpc.ankr.com/polygon/${ankrKey}`;
  return relayProviderResponse(await providerFetch(target, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body
  }), res);
}

const server = http.createServer(async (req, res) => {
  const requestUrl = new URL(req.url, `http://${req.headers.host || `${HOST}:${PORT}`}`);
  const pathname = requestUrl.pathname;

  try {
    if (pathname === '/' || pathname === '/api/status') {
      if (req.method !== 'GET' && req.method !== 'HEAD') return sendMethodNotAllowed(res);
      return sendJson(res, 200, {
        ok: true,
        service: 'liansfw-service-station-api',
        providers: providerStatus()
      });
    }

    if (!pathname.startsWith('/api/')) return sendJson(res, 404, { ok: false, error: 'Not Found' });
    if (!isAllowedWebsiteRequest(req)) return sendJson(res, 403, { ok: false, error: '请求来源无效' });
    if (!allowRequest(`api:${clientIp(req)}`, 120, 60 * 1000)) {
      return sendJson(res, 429, { ok: false, error: '请求过于频繁，请稍后再试' }, { 'Retry-After': '60' });
    }

    if (pathname.startsWith('/api/auth/')) return await walletAuth.handle(requestUrl, req, res);
    if (pathname === '/api/etherscan') return await handleEtherscan(requestUrl, req, res);
    if (pathname === '/api/coingecko') return await handleCoinGecko(requestUrl, req, res);
    if (pathname === '/api/goldrush') return await handleGoldRush(requestUrl, req, res);
    if (pathname === '/api/debank') return await handleDeBank(requestUrl, req, res);
    if (pathname === '/api/ankr') return await handleAnkr(requestUrl, req, res);
    if (pathname === '/api/rpc') return await handleRpc(requestUrl, req, res);
    if (pathname === '/api/chat') {
      if (req.method !== 'POST') return sendMethodNotAllowed(res);
      const rawBody = await readBody(req);
      try {
        req.body = rawBody ? JSON.parse(rawBody) : {};
      } catch {
        return sendJson(res, 400, { ok: false, error: 'JSON 格式无效' });
      }
      return await chatHandler(req, res);
    }
    return sendJson(res, 404, { ok: false, error: 'Not Found' });
  } catch (error) {
    console.error('[server]', error && error.name === 'AbortError' ? 'upstream timeout' : error && error.message);
    if (res.headersSent) return res.end();
    if (error && error.message === 'REQUEST_BODY_TOO_LARGE') {
      return sendJson(res, 413, { ok: false, error: '请求内容过大' });
    }
    return sendJson(res, error && error.name === 'AbortError' ? 504 : 502, {
      ok: false,
      error: error && error.name === 'AbortError' ? '上游 API 请求超时' : '上游 API 请求失败'
    });
  }
});

server.listen(PORT, HOST, () => {
  console.log(`API listening on http://${HOST}:${PORT}`);
});
