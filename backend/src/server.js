'use strict';
const http = require('node:http');
const { createApp } = require('./app');

const app = createApp();
const server = http.createServer(app.handler);
server.headersTimeout = 20e3;
server.requestTimeout = 60e3;
server.keepAliveTimeout = 5e3;
server.maxHeadersCount = 50;

server.listen(app.cfg.port, app.cfg.host, () => {
  console.log(`TrustVault listening on http://${app.cfg.host}:${app.cfg.port}`);
  if (app.svc.models.user.count() === 0) console.log('No users yet. Run "npm run seed" to create an administrator and demo accounts.');
});

for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, () => server.close(() => { app.close(); process.exit(0); }));
