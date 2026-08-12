# 链上服务站后端

这是 `https://lively-fuwz.netlify.app` 的后端 API，只保存程序代码，不包含任何 API Key。

## Render 部署

1. 在 Render 中选择 **New > Blueprint**。
2. 连接 GitHub 仓库 `Fonyunxz/liansfw-service-station`。
3. 按 `render.yaml` 创建 Web Service。
4. 在 Render 的 **Environment** 页面填写各项 API Key。
5. 等待部署完成，打开 `/api/status` 检查服务状态。

## 安全设计

- API Key 只从 Render 环境变量读取，不会进入浏览器或 GitHub。
- 仅接受来自 `APP_ORIGIN` 的网站请求。
- 钱包登录只验证消息签名，不索取助记词或私钥，也不会发起链上交易。
- 登录会话使用 `SESSION_SECRET` 签名，不依赖 Render 临时文件系统。
- 数据代理与 AI 接口均有按 IP 限流和请求体大小限制。

## Netlify 代理

Render 部署完成后，在 Netlify 前端的 `_redirects` 中加入：

```text
/api/*  https://你的服务名.onrender.com/api/:splat  200
```

这样浏览器始终访问 Netlify 自己的 `/api/*` 地址，钱包会话 Cookie 也保持在网站域名下。
