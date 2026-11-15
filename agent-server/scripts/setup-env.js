/**
 * Generate the agent .env file with a fresh random salt.
 * Writes .env (mode 600) next to server.js. Refuses to overwrite an
 * existing .env unless --force is passed. Never prints secret values.
 * Usage: node scripts/setup-env.js [--force]
 */
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const ENV_PATH = path.join(__dirname, '..', '.env');
const force = process.argv.includes('--force');

if (fs.existsSync(ENV_PATH) && !force) {
  console.log('env exists, refusing to overwrite (use --force to replace)');
  process.exit(0);
}

const salt = BigInt(`0x${crypto.randomBytes(16).toString('hex')}`).toString();
const lines = [
  'AGENT_GAMES_HMAC_SECRET=PLACEHOLDER',
  `STRATEGY_SALT=${salt}`,
  'STRATEGY_PARAMS=["10","50","50","0","0","0","0","0"]',
  'HMAC_KEY_ENCODING=utf8',
  'PORT=3123',
  '',
];
fs.writeFileSync(ENV_PATH, lines.join('\n'), { mode: 0o600 });
fs.chmodSync(ENV_PATH, 0o600);
console.log('env written: secret=placeholder, salt=set, params=set');
