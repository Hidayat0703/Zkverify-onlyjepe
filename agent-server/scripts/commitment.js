/**
 * Print the strategy commitment hash for dashboard registration.
 * Reads STRATEGY_SALT + STRATEGY_PARAMS from .env, computes
 * Poseidon(params[0..7], salt), and prints ONLY the 0x-prefixed 64-hex hash.
 * The salt and params are never printed.
 * Usage: node scripts/commitment.js
 */
'use strict';

const fs = require('fs');
const path = require('path');
const circomlibjs = require('circomlibjs');

function loadEnvFile(file) {
  const out = {};
  for (const line of fs.readFileSync(file, 'utf8').split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eq = trimmed.indexOf('=');
    if (eq <= 0) continue;
    out[trimmed.slice(0, eq).trim()] = trimmed.slice(eq + 1).trim();
  }
  return out;
}

async function main() {
  const env = loadEnvFile(path.join(__dirname, '..', '.env'));
  const params = JSON.parse(env.STRATEGY_PARAMS);
  const poseidon = await circomlibjs.buildPoseidon();
  const commitment = poseidon.F.toObject(
    poseidon([...params.map((p) => BigInt(p)), BigInt(env.STRATEGY_SALT)]),
  );
  console.log(`COMMITMENT_HASH=0x${commitment.toString(16).padStart(64, '0')}`);
}

main().catch(() => {
  console.error('commitment computation failed');
  process.exit(1);
});
