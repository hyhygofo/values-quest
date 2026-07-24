// Vercel serverless 入口：直接复用 server.js 导出的请求处理器（零额外依赖）
module.exports = require('../server.js');
