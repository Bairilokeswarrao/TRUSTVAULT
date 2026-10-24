'use strict';
// Creates one admin + demo owners/viewer with RANDOM passwords, printed once. Pass --admin-only for just the admin.
const crypto = require('node:crypto');
const { createApp } = require('./app');

(async () => {
  const app = createApp();
  const { svc } = app;
  const { models } = svc;
  const pw = () => crypto.randomBytes(12).toString('base64url');
  const accounts = process.argv.includes('--admin-only')
    ? [['admin@trustvault.local', 'Admin', 'admin']]
    : [['admin@trustvault.local', 'Ada Admin', 'admin'], ['alice@trustvault.local', 'Alice Owner', 'owner'],
       ['bob@trustvault.local', 'Bob Owner', 'owner'], ['carol@trustvault.local', 'Carol Viewer', 'viewer']];
  for (const [email, name, role] of accounts) {
    if (models.user.findByEmail(email)) { console.log(`exists  ${email}`); continue; }
    const password = pw();
    const id = models.user.create({ email, name, role, passwordHash: await svc.password.hash(password) });
    svc.audit.append({ action: 'user_created', targetUserId: id, detail: { email, role, via: 'seed' } });
    console.log(`created ${role.padEnd(6)} ${email}  password: ${password}`);
  }
  console.log('Passwords are shown once. Change them after first sign-in.');
  app.close();
})();
