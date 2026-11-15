/**
 * Local end-to-end tests for server.js. Spawns the server on PORT=3124,
 * signs requests with the .env HMAC secret, and verifies responses
 * (including Groth16 proof verification against the exported VK).
 * Never prints secret values. Exits non-zero on any failure.
 * Usage: node scripts/test-local.js
 */
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const snarkjs = require('snarkjs');
const circomlibjs = require('circomlibjs');

const DIR = path.join(__dirname, '..');
const PORT = 3124;
const BASE = `http://127.0.0.1:${PORT}`;

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

const env = loadEnvFile(path.join(DIR, '.env'));
const SECRET = env.AGENT_GAMES_HMAC_SECRET || '';
const SALT = env.STRATEGY_SALT || '';
const PARAMS = JSON.parse(env.STRATEGY_PARAMS);

function sign(bytes) {
  return crypto.createHmac('sha256', Buffer.from(SECRET, 'utf8')).update(bytes).digest('hex');
}

async function post(pathname, bodyObj, { signature = null, rawBody = null } = {}) {
  const body = rawBody !== null ? rawBody : JSON.stringify(bodyObj);
  const headers = { 'content-type': 'application/json' };
  if (signature !== null) headers['x-agent-games-signature'] = signature;
  else if (rawBody !== null || bodyObj !== undefined) headers['x-agent-games-signature'] = sign(Buffer.from(body, 'utf8'));
  const res = await fetch(`${BASE}${pathname}`, { method: 'POST', headers, body });
  const buf = Buffer.from(await res.arrayBuffer());
  let json = null;
  try { json = JSON.parse(buf.toString('utf8')); } catch { /* keep null */ }
  return { status: res.status, headers: res.headers, bodyBuf: buf, json };
}

function responseSignatureValid(resp) {
  const header = resp.headers.get('x-agent-games-signature');
  if (!header || !/^[a-fA-F0-9]{64}$/.test(header)) return false;
  return crypto.timingSafeEqual(Buffer.from(sign(resp.bodyBuf), 'hex'), Buffer.from(header, 'hex'));
}

function envelope({ matchId, turn, selfBalance, opponentBalance, mode = 'competition', deadlineMs = Date.now() + 300000, commitmentHash }) {
  return {
    protocolVersion: 'v1',
    eventId: 'steal-the-vfy',
    mode,
    matchId,
    turn,
    issuedAt: new Date().toISOString(),
    deadlineAt: new Date(deadlineMs).toISOString(),
    state: { selfBalance: String(selfBalance), opponentBalance: String(opponentBalance), selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: null },
    strategyCommitment: { hash: commitmentHash },
    resolverVersion: 'v1',
    nonce: crypto.randomBytes(8).toString('hex'),
  };
}

const MATCH_ID = '123e4567-e89b-12d3-a456-426614174000';
let failures = 0;
function check(name, ok, detail = '') {
  console.log(`${ok ? 'PASS' : 'FAIL'} ${name}${detail ? ` — ${detail}` : ''}`);
  if (!ok) failures += 1;
}

async function main() {
  const poseidon = await circomlibjs.buildPoseidon();
  const F = poseidon.F;
  const H = (arr) => F.toObject(poseidon(arr.map(BigInt)));
  const commitment = H([...PARAMS.map(BigInt), BigInt(SALT)]);
  const commitmentHash = `0x${commitment.toString(16).padStart(64, '0')}`;
  const commitmentDecimal = commitment.toString();
  const vk = await snarkjs.zKey.exportVerificationKey(path.join(DIR, 'vfy-policy_final.zkey'));

  const child = spawn('node', ['server.js'], {
    cwd: DIR,
    env: { ...process.env, PORT: String(PORT) },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let serverLog = '';
  child.stdout.on('data', (d) => { serverLog += d.toString(); });
  child.stderr.on('data', (d) => { serverLog += d.toString(); });

  const ready = await new Promise((resolve) => {
    const t0 = Date.now();
    const iv = setInterval(() => {
      if (serverLog.includes('"kind":"ready"')) { clearInterval(iv); resolve(true); }
      else if (Date.now() - t0 > 30000) { clearInterval(iv); resolve(false); }
    }, 200);
  });
  if (!ready) {
    console.log('FAIL server did not become ready');
    console.log(serverLog.slice(0, 2000));
    child.kill('SIGTERM');
    process.exit(1);
  }

  try {
    // 1. Preflight on /
    {
      const r = await post('/', { type: 'agent-games.preflight.v1', agent_id: 'agt_test', issued_at: new Date().toISOString(), nonce: 'abc123' });
      check('preflight / returns 200 + ok body + valid signature', r.status === 200 && r.json && r.json.ok === true && r.json.protocolVersion === 'v1' && responseSignatureValid(r), `status=${r.status}`);
    }
    // 2. Preflight on /agent
    {
      const r = await post('/agent', { type: 'agent-games.preflight.v1', agent_id: 'agt_test', issued_at: new Date().toISOString(), nonce: 'abc123' });
      check('preflight /agent returns 200', r.status === 200 && r.json && r.json.ok === true, `status=${r.status}`);
    }
    // 3. EXTRACT branch + proof verification
    {
      const r = await post('/agent', envelope({ matchId: MATCH_ID, turn: 7, selfBalance: 100, opponentBalance: 100, commitmentHash }));
      const sig = r.json && r.json.public_signals;
      const expectedOut = H([BigInt(`0x${MATCH_ID.replace(/-/g, '')}`), 7n, 1n]).toString();
      const verified = sig ? await snarkjs.groth16.verify(vk, sig, r.json.proof) : false;
      const ok = r.status === 200 && r.json.action.type === 'EXTRACT' && r.json.action.amount === 10
        && Array.isArray(sig) && sig.length === 9 && sig[6] === '2' && sig[7] === '10'
        && sig[1] === commitmentDecimal && sig[0] === expectedOut && verified
        && typeof r.json.policyProof.publicInputsHash === 'string' && r.json.policyProof.publicInputsHash.startsWith('0x')
        && responseSignatureValid(r);
      check('EXTRACT turn: proof verifies, signals in order, OUT bound', ok, `status=${r.status} action=${r.json && r.json.action && r.json.action.type} verified=${verified}`);
    }
    // 4. FORTIFY branch
    {
      const r = await post('/agent', envelope({ matchId: MATCH_ID, turn: 8, selfBalance: 40, opponentBalance: 100, commitmentHash }));
      const sig = r.json && r.json.public_signals;
      const verified = sig ? await snarkjs.groth16.verify(vk, sig, r.json.proof) : false;
      const ok = r.status === 200 && r.json.action.type === 'FORTIFY' && !('amount' in r.json.action)
        && sig && sig[6] === '1' && sig[7] === '0' && verified;
      check('FORTIFY turn: no amount field, proof verifies', ok, `status=${r.status} verified=${verified}`);
    }
    // 5. HOLD branch (practice mode tolerated)
    {
      const r = await post('/agent', envelope({ matchId: MATCH_ID, turn: 9, selfBalance: 100, opponentBalance: 40, mode: 'practice', commitmentHash }));
      const sig = r.json && r.json.public_signals;
      const verified = sig ? await snarkjs.groth16.verify(vk, sig, r.json.proof) : false;
      const ok = r.status === 200 && r.json.action.type === 'HOLD' && !('amount' in r.json.action)
        && sig && sig[6] === '0' && sig[7] === '0' && verified;
      check('HOLD turn: proof verifies', ok, `status=${r.status} verified=${verified}`);
    }
    // 6. Tampered body -> 401
    {
      const good = JSON.stringify({ type: 'agent-games.preflight.v1', agent_id: 'agt_test', issued_at: new Date().toISOString(), nonce: 'abc123' });
      const sig = sign(Buffer.from(good, 'utf8'));
      const tampered = good.replace('agt_test', 'agt_tesX');
      const r = await post('/', null, { signature: sig, rawBody: tampered });
      check('tampered body -> 401', r.status === 401, `status=${r.status}`);
    }
    // 7. Missing signature -> 401
    {
      const res = await fetch(`${BASE}/`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
      check('missing signature -> 401', res.status === 401, `status=${res.status}`);
    }
    // 8. GET with valid signature over empty body -> 400
    {
      const sig = sign(Buffer.alloc(0));
      const res = await fetch(`${BASE}/`, { method: 'GET', headers: { 'x-agent-games-signature': sig } });
      check('GET with valid signature -> 400', res.status === 400, `status=${res.status}`);
    }
    // 9. Invalid JSON with valid signature -> 400
    {
      const r = await post('/', null, { rawBody: '{not json' });
      check('invalid JSON -> 400', r.status === 400, `status=${r.status}`);
    }
    // 10. Expired deadline -> HOLD without proof
    {
      const r = await post('/agent', envelope({ matchId: MATCH_ID, turn: 10, selfBalance: 100, opponentBalance: 100, deadlineMs: Date.now() - 1000, commitmentHash }));
      const ok = r.status === 200 && r.json.action.type === 'HOLD' && !('proof' in r.json) && !('public_signals' in r.json);
      check('expired deadline -> HOLD, no proof', ok, `status=${r.status}`);
    }
  } finally {
    child.kill('SIGTERM');
  }

  console.log(failures === 0 ? 'ALL TESTS PASSED' : `${failures} TEST(S) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error('harness error:', e && e.name ? e.name : 'Error');
  process.exit(1);
});
