'use strict';

const DEEPSEEK_URL = 'https://api.deepseek.com/chat/completions';
const DEFAULT_MODEL = 'deepseek-v4-flash';
const WINDOW_MS = 60 * 1000;
const MAX_PER_WINDOW = 5;
const rateMap = new Map();

function getIp(req) {
  return String(
    req.headers['cf-connecting-ip'] ||
    req.headers['x-nf-client-connection-ip'] ||
    (req.headers['x-forwarded-for'] && String(req.headers['x-forwarded-for']).split(',')[0].trim()) ||
    req.headers['x-real-ip'] ||
    (req.socket && req.socket.remoteAddress) ||
    'unknown'
  );
}

function allow(ip) {
  const now = Date.now();
  const row = rateMap.get(ip) || { count: 0, startedAt: now };
  if (now - row.startedAt >= WINDOW_MS) {
    row.count = 0;
    row.startedAt = now;
  }
  row.count += 1;
  rateMap.set(ip, row);
  return row.count <= MAX_PER_WINDOW;
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

function systemPrompt(lang) {
  const languageName = {
    'zh-cn': '简体中文',
    'zh-tw': '繁體中文',
    en: 'English',
    ja: '日本語'
  }[lang] || '简体中文';

  return [
    '你是「链上服务站」的 AI 助手，面向 Origin、Awake、Anubis 生态用户。',
    `必须使用${languageName}回答。`,
    '只提供信息与操作指引，不构成投资建议。',
    '不要编造实时链上数据；不确定时明确说明。',
    '绝不索要助记词、私钥、验证码或钱包密码。',
    '回答应简洁、分点、可执行。'
  ].join('\n');
}

module.exports = async function chatHandler(req, res) {
  if (req.method !== 'POST') return sendJson(res, 405, { error: 'Method Not Allowed' });
  if (!allow(getIp(req))) return sendJson(res, 429, { error: '请求过于频繁，请稍后再试' });

  const body = req.body && typeof req.body === 'object' ? req.body : {};
  const message = String(body.message || '').trim();
  const lang = ['zh-cn', 'zh-tw', 'en', 'ja'].includes(body.lang) ? body.lang : 'zh-cn';
  const officialContext = String(body.officialContext || '').slice(0, 12000);
  const imaContext = String(body.imaContext || '').slice(0, 8000);

  if (!message) return sendJson(res, 400, { error: 'message 不能为空' });
  if (message.length > 500) return sendJson(res, 400, { error: '消息过长（最多 500 字）' });

  const apiKey = process.env.DEEPSEEK_API_KEY;
  if (!apiKey) return sendJson(res, 503, { error: '服务未配置 DEEPSEEK_API_KEY' });

  const context = [
    '【站点官方知识】', officialContext || '无', '',
    '【用户知识库参考（仅供参考，可能不完整）】', imaContext || '无', '',
    '【用户问题】', message
  ].join('\n');

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 30000);
  try {
    const upstream = await fetch(DEEPSEEK_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${apiKey}`
      },
      body: JSON.stringify({
        model: process.env.DEEPSEEK_MODEL || DEFAULT_MODEL,
        messages: [
          { role: 'system', content: systemPrompt(lang) },
          { role: 'user', content: context }
        ],
        max_tokens: 800,
        temperature: 0.5,
        stream: false
      }),
      signal: controller.signal
    });

    if (!upstream.ok) {
      console.error('[deepseek] upstream status:', upstream.status);
      return sendJson(res, 502, { error: '模型服务暂时不可用' });
    }

    const data = await upstream.json();
    const reply = data && data.choices && data.choices[0] && data.choices[0].message
      ? data.choices[0].message.content
      : '';
    return sendJson(res, 200, {
      reply: reply || '暂时无法生成回答，请稍后再试。',
      links: [
        { text: '学习学院', url: '/learn.html' },
        { text: '工具箱', url: '/tools.html' }
      ]
    });
  } catch (error) {
    console.error('[deepseek]', error && error.name === 'AbortError' ? 'timeout' : 'request failed');
    return sendJson(res, error && error.name === 'AbortError' ? 504 : 502, {
      error: error && error.name === 'AbortError' ? '模型服务请求超时' : '模型服务暂时不可用'
    });
  } finally {
    clearTimeout(timer);
  }
};
