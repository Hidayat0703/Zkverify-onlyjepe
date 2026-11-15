/**
 * takanome-steal-vfy — box-hosted Agent Games / Steal the VFY agent (Node.js).
 *
 * Spec sources (captured 2026-11-15, see spec-capture/):
 * - Turn envelope + union response schema, publicInputsHash (keccak256 over
 *   ABI-packed 32-byte big-endian fields), HMAC-SHA256 hex over the raw body,
 *   preflight {type:"agent-games.preflight.v1"} -> {ok:true, protocolVersion:"v1"}.
 * - Circuit (circuit-analysis/FINDINGS.md, PROVEN):
 *   commitment = Poseidon(strategyParams[0..7], salt), salt last;
 *   public signals [OUT, commitment, matchId, turn, selfBalance,
 *   opponentBalance, action, amount, circuitVersion];
 *   policy: FORTIFY if selfBalance < params[1], else EXTRACT (amount params[0])
 *   if opponentBalance > params[2] and params[3]==0, else HOLD.
 *
 * Env (in .env, mode 600, never committed):
 *   AGENT_GAMES_HMAC_SECRET — platform-generated secret. Required; the server
 *     fails closed (HTTP 500) when it is missing or empty.
 *   STRATEGY_SALT — decimal string, random 128-bit, generated on the host.
 *   STRATEGY_PARAMS — JSON array of 8 decimal strings.
 *     params[4..7] must be "0".
 *   HMAC_KEY_ENCODING — "utf8" (default, presumed: UTF-8 bytes of the secret
 *     string) or "hex" (fallback: hex-decoded secret bytes as the HMAC key).
 *   PORT — default 3123. Binds 127.0.0.1 only; public exposure via tunnel.
 *
 * Security: secrets are never logged. Logs carry only booleans, action types,
 * match ids/turns, and timings. Kurier submission is NOT wired: no
 * proofReference is emitted. Fail closed: any error after authentication
 * yields HOLD with no proof.
 */
'use strict';

const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const snarkjs = require('snarkjs');
const circomlibjs = require('circomlibjs');

// ---------------------------------------------------------------- env -----

function loadEnvFile(file) {
  const out = {};
  if (!fs.existsSync(file)) return out;
  for (const line of fs.readFileSync(file, 'utf8').split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eq = trimmed.indexOf('=');
    if (eq <= 0) continue;
    out[trimmed.slice(0, eq).trim()] = trimmed.slice(eq + 1).trim();
  }
  return out;
}

const fileEnv = loadEnvFile(path.join(__dirname, '.env'));
const getEnv = (name) => (process.env[name] !== undefined ? process.env[name] : fileEnv[name]);

const PORT = Number(getEnv('PORT') || 3123);
const HOST = '127.0.0.1';
const SECRET = getEnv('AGENT_GAMES_HMAC_SECRET') || '';
const SALT = getEnv('STRATEGY_SALT') || '';
const HMAC_KEY_ENCODING = getEnv('HMAC_KEY_ENCODING') || 'utf8';

let PARAMS = null;
try {
  PARAMS = JSON.parse(getEnv('STRATEGY_PARAMS') || 'null');
} catch {
  PARAMS = null;
}

function validateParams(params) {
  if (!Array.isArray(params) || params.length !== 8) return false;
  if (!params.every((p) => typeof p === 'string' && /^\d+$/.test(p))) return false;
  const n = params.map((p) => BigInt(p));
  if (n[0] < 1n || n[0] > 10n) return false;
  if (n[3] !== 0n && n[3] !== 1n) return false;
  if (n[4] !== 0n || n[5] !== 0n || n[6] !== 0n || n[7] !== 0n) return false;
  return true;
}

if (!validateParams(PARAMS)) {
  console.error(JSON.stringify({ kind: 'fatal', error: 'invalid STRATEGY_PARAMS' }));
  process.exit(1);
}
if (!/^\d+$/.test(SALT)) {
  console.error(JSON.stringify({ kind: 'fatal', error: 'invalid STRATEGY_SALT' }));
  process.exit(1);
}

// ------------------------------------------------------------- keccak ----
// Keccak-256 (0x01 domain suffix, NOT SHA3). Ported from the tested worker.js.

const MASK64 = (1n << 64n) - 1n;
const MAX_UINT256 = (1n << 256n) - 1n;
const ROTATIONS = [
  0, 1, 62, 28, 27,
  36, 44, 6, 55, 20,
  3, 10, 43, 25, 39,
  41, 45, 15, 21, 8,
  18, 2, 61, 56, 14,
];
const ROUND_CONSTANTS = [
  0x0000000000000001n, 0x0000000000008082n,
  0x800000000000808an, 0x8000000080008000n,
  0x000000000000808bn, 0x0000000080000001n,
  0x8000000080008081n, 0x8000000000008009n,
  0x000000000000008an, 0x0000000000000088n,
  0x0000000080008009n, 0x000000008000000an,
  0x000000008000808bn, 0x800000000000008bn,
  0x8000000000008089n, 0x8000000000008003n,
  0x8000000000008002n, 0x8000000000000080n,
  0x000000000000800an, 0x800000008000000an,
  0x8000000080008081n, 0x8000000000008080n,
  0x0000000080000001n, 0x8000000080008008n,
];

function bytesToHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function rotate64(value, shift) {
  const n = BigInt(shift);
  return ((value << n) | (value >> (64n - n))) & MASK64;
}

function keccakPermutation(a) {
  const c = new Array(5);
  const d = new Array(5);
  const b = new Array(25);
  for (const rc of ROUND_CONSTANTS) {
    for (let x = 0; x < 5; x++) {
      c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
    }
    for (let x = 0; x < 5; x++) {
      d[x] = c[(x + 4) % 5] ^ rotate64(c[(x + 1) % 5], 1);
    }
    for (let y = 0; y < 5; y++) {
      for (let x = 0; x < 5; x++) {
        const i = x + 5 * y;
        a[i] ^= d[x];
        b[y + 5 * ((2 * x + 3 * y) % 5)] = rotate64(a[i], ROTATIONS[i]);
      }
    }
    for (let y = 0; y < 5; y++) {
      for (let x = 0; x < 5; x++) {
        a[x + 5 * y] =
          b[x + 5 * y] ^
          ((~b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y]);
      }
    }
    a[0] ^= rc;
  }
}

function keccak256(bytes) {
  const rate = 136;
  const padded = new Uint8Array(Math.ceil((bytes.length + 1) / rate) * rate);
  padded.set(bytes);
  padded[bytes.length] = 0x01;
  padded[padded.length - 1] |= 0x80;
  const state = new Array(25).fill(0n);
  for (let offset = 0; offset < padded.length; offset += rate) {
    for (let i = 0; i < rate; i++) {
      state[i >> 3] ^= BigInt(padded[offset + i]) << BigInt((i & 7) * 8);
    }
    keccakPermutation(state);
  }
  const result = new Uint8Array(32);
  for (let i = 0; i < result.length; i++) {
    result[i] = Number((state[i >> 3] >> BigInt((i & 7) * 8)) & 255n);
  }
  return `0x${bytesToHex(result)}`;
}

// --------------------------------------------------------------- hmac -----

function hmacKey() {
  if (!SECRET) throw new Error('HMAC key unavailable');
  if (HMAC_KEY_ENCODING === 'hex') {
    if (!/^[a-fA-F0-9]+$/.test(SECRET) || SECRET.length % 2 !== 0) {
      throw new Error('HMAC key is not valid hex');
    }
    return Buffer.from(SECRET, 'hex');
  }
  return Buffer.from(SECRET, 'utf8');
}

function hmacSha256Hex(bytes) {
  return crypto.createHmac('sha256', hmacKey()).update(bytes).digest('hex');
}

function signaturesEqual(expectedHex, headerValue) {
  const text = typeof headerValue === 'string' ? headerValue.replace(/^sha256=/i, '') : '';
  if (!/^[a-fA-F0-9]{64}$/.test(text)) return false;
  return crypto.timingSafeEqual(Buffer.from(expectedHex, 'hex'), Buffer.from(text, 'hex'));
}

// ----------------------------------------------------------- validation ---

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function nonEmptyString(value, name) {
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new Error(`${name} must be a non-empty string`);
  }
  return value;
}

function turnNumber(value, name) {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`${name} must be a non-negative safe integer`);
  }
  return value;
}

function uint256(value, name) {
  let n;
  if (typeof value === 'bigint') {
    n = value;
  } else if (typeof value === 'number' && Number.isSafeInteger(value)) {
    n = BigInt(value);
  } else if (typeof value === 'string' && /^\d+$/.test(value)) {
    n = BigInt(value);
  } else {
    throw new Error(`${name} must be an unsigned integer`);
  }
  if (n < 0n || n > MAX_UINT256) {
    throw new Error(`${name} does not fit in 32 bytes`);
  }
  return n;
}

function balance(value, name) {
  if (typeof value !== 'string' || !/^\d+$/.test(value)) {
    throw new Error(`${name} must be a decimal string`);
  }
  return uint256(value, name);
}

function commitmentValue(value) {
  if (typeof value !== 'string' || !/^0x[a-fA-F0-9]{64}$/.test(value)) {
    throw new Error('strategyCommitment.hash must be a 32-byte 0x hash');
  }
  return BigInt(value);
}

function matchIdValue(matchId) {
  nonEmptyString(matchId, 'matchId');
  const hex = matchId.replace(/-/g, '');
  if (!/^[a-fA-F0-9]{1,64}$/.test(hex)) {
    throw new Error('matchId must encode at most 32 bytes of hexadecimal');
  }
  return BigInt(`0x${hex}`);
}

function parseTimestamp(value) {
  if (typeof value === 'number' && Number.isFinite(value)) {
    const ms = Math.abs(value) < 1e11 ? value * 1000 : value;
    return Number.isFinite(new Date(ms).getTime()) ? ms : null;
  }
  if (typeof value === 'string') {
    const ms = Date.parse(value);
    return Number.isFinite(ms) ? ms : null;
  }
  return null;
}

function validateTurnEnvelope(obj) {
  if (!isRecord(obj)) throw new Error('Envelope must be an object');
  if (obj.protocolVersion !== 'v1') throw new Error('Invalid protocolVersion');
  if (obj.eventId !== 'steal-the-vfy') throw new Error('Invalid eventId');
  const matchId = nonEmptyString(obj.matchId, 'matchId');
  const turn = turnNumber(obj.turn, 'turn');
  if (typeof obj.mode !== 'string') throw new Error('mode must be a string');
  for (const field of ['resolverVersion', 'issuedAt', 'deadlineAt']) {
    if (!Object.hasOwn(obj, field)) throw new Error(`${field} is required`);
  }
  if (!isRecord(obj.state)) throw new Error('state is required');
  if (!isRecord(obj.strategyCommitment)) {
    throw new Error('strategyCommitment is required');
  }
  commitmentValue(obj.strategyCommitment.hash);
  const fortified = (value, name) => (value === null ? null : turnNumber(value, name));
  return {
    protocolVersion: obj.protocolVersion,
    eventId: obj.eventId,
    mode: obj.mode,
    matchId,
    turn,
    issuedAt: obj.issuedAt,
    deadlineAt: obj.deadlineAt,
    state: {
      selfBalance: balance(obj.state.selfBalance, 'selfBalance'),
      opponentBalance: balance(obj.state.opponentBalance, 'opponentBalance'),
      selfFortifiedUntilTurn: fortified(obj.state.selfFortifiedUntilTurn, 'selfFortifiedUntilTurn'),
      opponentFortifiedUntilTurn: fortified(obj.state.opponentFortifiedUntilTurn, 'opponentFortifiedUntilTurn'),
    },
    strategyCommitment: { hash: obj.strategyCommitment.hash },
    resolverVersion: obj.resolverVersion,
    nonce: nonEmptyString(obj.nonce, 'nonce'),
    issuedAtMs: parseTimestamp(obj.issuedAt),
    deadlineAtMs: parseTimestamp(obj.deadlineAt),
  };
}

function validatePreflight(obj) {
  nonEmptyString(obj.agent_id, 'agent_id');
  if (!Object.hasOwn(obj, 'issued_at')) throw new Error('issued_at is required');
  nonEmptyString(obj.nonce, 'nonce');
}

// ------------------------------------------------------ actions + hash ----

const EXTRACT_MAX = 10;

function normalizeAction(action) {
  if (!isRecord(action)) return { type: 'HOLD' };
  if (action.type === 'HOLD' || action.type === 'FORTIFY') {
    return { type: action.type };
  }
  if (
    action.type === 'EXTRACT' &&
    Number.isInteger(action.amount) &&
    action.amount >= 1 &&
    action.amount <= EXTRACT_MAX
  ) {
    return { type: 'EXTRACT', amount: action.amount };
  }
  return { type: 'HOLD' };
}

function actionFields(action) {
  const normalized = normalizeAction(action);
  return {
    actionEnum: { HOLD: 0, FORTIFY: 1, EXTRACT: 2 }[normalized.type],
    amount: normalized.type === 'EXTRACT' ? normalized.amount : 0,
  };
}

// The circuit policy, exactly as proven in FINDINGS.md §3. Params are BigInts.
function decideAction(envelope, paramsBig) {
  const selfBalance = envelope.state.selfBalance;
  const opponentBalance = envelope.state.opponentBalance;
  const lowBalance = selfBalance < paramsBig[1];
  const oppRich = opponentBalance > paramsBig[2];
  const shouldExtract = oppRich && paramsBig[3] === 0n && !lowBalance;
  if (lowBalance) return { type: 'FORTIFY' };
  if (shouldExtract) return { type: 'EXTRACT', amount: Number(paramsBig[0]) };
  return { type: 'HOLD' };
}

function packPublicInputs({ commitment, matchId, turn, selfBalance, opponentBalance, actionEnum, amount, circuitVersion }) {
  if (circuitVersion !== 'v1') throw new Error('Unsupported circuitVersion');
  const action = uint256(actionEnum, 'actionEnum');
  const quantity = uint256(amount, 'amount');
  if (action > 2n) throw new Error('Invalid action enum');
  if (
    (action === 2n && (quantity < 1n || quantity > 10n)) ||
    (action !== 2n && quantity !== 0n)
  ) {
    throw new Error('Invalid action amount');
  }
  const words = [
    commitmentValue(commitment),
    matchIdValue(matchId),
    uint256(turn, 'turn'),
    uint256(selfBalance, 'selfBalance'),
    uint256(opponentBalance, 'opponentBalance'),
    action,
    quantity,
    1n,
  ];
  const packed = new Uint8Array(256);
  words.forEach((word, index) => {
    for (let i = 31; i >= 0; i--) {
      packed[index * 32 + i] = Number(word & 255n);
      word >>= 8n;
    }
  });
  return packed;
}

function computePublicInputsHash(fields) {
  return keccak256(packPublicInputs(fields));
}

function hashForAction(envelope, action) {
  return computePublicInputsHash({
    commitment: envelope.strategyCommitment.hash,
    matchId: envelope.matchId,
    turn: envelope.turn,
    selfBalance: envelope.state.selfBalance,
    opponentBalance: envelope.state.opponentBalance,
    ...actionFields(action),
    circuitVersion: 'v1',
  });
}

function deriveIdempotencyKey(matchId, turn) {
  const hex = crypto.createHash('sha256').update(`${matchId}:${turn}`, 'utf8').digest('hex').slice(0, 32);
  return [hex.slice(0, 8), hex.slice(8, 12), hex.slice(12, 16), hex.slice(16, 20), hex.slice(20, 32)].join('-');
}

function buildTurnResponse(envelope, action, { proof, publicSignals } = {}) {
  const normalized = normalizeAction(action);
  const realProof = isRecord(proof) && Object.keys(proof).length > 0 && Array.isArray(publicSignals);
  const policyProof = { circuitVersion: 'v1', publicInputsHash: hashForAction(envelope, normalized) };
  const response = {
    matchId: envelope.matchId,
    turn: envelope.turn,
    action: normalized,
    policyProof,
    agentTimestamp: new Date().toISOString(),
    idempotencyKey: deriveIdempotencyKey(envelope.matchId, envelope.turn),
  };
  if (realProof) {
    response.proof = proof;
    response.public_signals = publicSignals;
  }
  return response;
}

// --------------------------------------------------------------- prover ---

const WASM_PATH = path.join(__dirname, 'vfy-policy.wasm');
const ZKEY_PATH = path.join(__dirname, 'vfy-policy_final.zkey');
const PARAMS_BIG = PARAMS.map((p) => BigInt(p));

let VK = null;
let COMMITMENT_BIGINT = null;
let COMMITMENT_DECIMAL = null;

async function initCrypto() {
  const poseidon = await circomlibjs.buildPoseidon();
  const F = poseidon.F;
  COMMITMENT_BIGINT = F.toObject(poseidon([...PARAMS_BIG, BigInt(SALT)]));
  COMMITMENT_DECIMAL = COMMITMENT_BIGINT.toString();
  VK = await snarkjs.zKey.exportVerificationKey(ZKEY_PATH);
}

function commitmentHex() {
  return `0x${COMMITMENT_BIGINT.toString(16).padStart(64, '0')}`;
}

async function generatePolicyProof(envelope, action) {
  const fields = actionFields(action);
  const input = {
    action: String(fields.actionEnum),
    amount: String(fields.amount),
    circuitVersion: '1',
    commitment: COMMITMENT_DECIMAL,
    matchId: matchIdValue(envelope.matchId).toString(),
    opponentBalance: envelope.state.opponentBalance.toString(),
    salt: BigInt(SALT).toString(),
    selfBalance: envelope.state.selfBalance.toString(),
    strategyParams: PARAMS.map(String),
    turnNumber: String(envelope.turn),
  };
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM_PATH, ZKEY_PATH);
  const ok = await snarkjs.groth16.verify(VK, publicSignals, proof);
  if (!ok) throw new Error('local proof verification failed');
  return { proof, publicSignals };
}

// ---------------------------------------------------------------- http ----

function log(obj) {
  console.log(JSON.stringify({ ts: new Date().toISOString(), ...obj }));
}

function sendJson(res, status, obj) {
  const bytes = Buffer.from(JSON.stringify(obj), 'utf8');
  const headers = { 'content-type': 'application/json' };
  if (SECRET) {
    try {
      headers['x-agent-games-signature'] = hmacSha256Hex(bytes);
    } catch {
      // Signing failure: never emit an unsigned success body.
      res.writeHead(500, { 'content-type': 'application/json' });
      res.end('{"error":"Internal server error"}');
      return;
    }
  }
  res.writeHead(status, headers);
  res.end(bytes);
}

async function processTurn(envelope) {
  const t0 = Date.now();
  const commitmentMatch =
    envelope.strategyCommitment.hash.toLowerCase() === commitmentHex().toLowerCase();
  if (envelope.deadlineAtMs !== null && envelope.deadlineAtMs <= Date.now()) {
    log({ kind: 'turn', matchId: envelope.matchId, turn: envelope.turn, action: 'HOLD', reason: 'expired', commitmentMatch, latencyMs: Date.now() - t0 });
    return buildTurnResponse(envelope, { type: 'HOLD' });
  }
  let action = decideAction(envelope, PARAMS_BIG);
  try {
    hashForAction(envelope, action);
    const generated = await generatePolicyProof(envelope, action);
    log({ kind: 'turn', matchId: envelope.matchId, turn: envelope.turn, action: action.type, proofOk: true, commitmentMatch, latencyMs: Date.now() - t0 });
    return buildTurnResponse(envelope, action, generated);
  } catch (error) {
    log({ kind: 'turn', matchId: envelope.matchId, turn: envelope.turn, action: 'HOLD', reason: 'proof-error', errorClass: error && error.name ? error.name : 'Error', commitmentMatch, latencyMs: Date.now() - t0 });
    return buildTurnResponse(envelope, { type: 'HOLD' });
  }
}

const MAX_BODY_BYTES = 1024 * 1024;

function handleRequest(req, res) {
  const chunks = [];
  let total = 0;
  let aborted = false;
  req.on('data', (chunk) => {
    total += chunk.length;
    if (total > MAX_BODY_BYTES) {
      aborted = true;
      req.destroy();
      return;
    }
    chunks.push(chunk);
  });
  req.on('error', () => {
    try { res.destroy(); } catch { /* ignore */ }
  });
  req.on('end', async () => {
    if (aborted) return;
    const rawBytes = Buffer.concat(chunks);
    let authenticated = false;
    let envelope = null;
    let rawObject = null;
    try {
      if (!SECRET) {
        res.writeHead(500, { 'content-type': 'application/json' });
        res.end('{"error":"Internal server error"}');
        return;
      }
      let expected;
      try {
        expected = hmacSha256Hex(rawBytes);
      } catch {
        res.writeHead(500, { 'content-type': 'application/json' });
        res.end('{"error":"Internal server error"}');
        return;
      }
      const hmacOk = signaturesEqual(expected, req.headers['x-agent-games-signature']);
      if (!hmacOk) {
        log({ kind: 'auth', hmacOk: false, method: req.method, path: req.url });
        sendJson(res, 401, { error: 'Unauthorized' });
        return;
      }
      authenticated = true;

      if (req.method !== 'POST') {
        sendJson(res, 400, { error: 'Bad request' });
        return;
      }
      try {
        rawObject = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(rawBytes));
      } catch {
        sendJson(res, 400, { error: 'Bad request' });
        return;
      }

      if (isRecord(rawObject) && rawObject.type === 'agent-games.preflight.v1') {
        try {
          validatePreflight(rawObject);
        } catch {
          sendJson(res, 400, { error: 'Bad request' });
          return;
        }
        log({ kind: 'preflight', hmacOk: true });
        sendJson(res, 200, { ok: true, protocolVersion: 'v1' });
        return;
      }

      try {
        envelope = validateTurnEnvelope(rawObject);
        hashForAction(envelope, { type: 'HOLD' });
      } catch {
        sendJson(res, 400, { error: 'Bad request' });
        return;
      }

      sendJson(res, 200, await processTurn(envelope));
    } catch {
      if (authenticated && rawObject) {
        try {
          envelope = envelope || validateTurnEnvelope(rawObject);
          log({ kind: 'turn', matchId: envelope.matchId, turn: envelope.turn, action: 'HOLD', reason: 'catch-all' });
          sendJson(res, 200, buildTurnResponse(envelope, { type: 'HOLD' }));
          return;
        } catch { /* fall through */ }
      }
      try {
        sendJson(res, authenticated ? 400 : 500, { error: authenticated ? 'Bad request' : 'Internal server error' });
      } catch {
        res.writeHead(500, { 'content-type': 'application/json' });
        res.end('{"error":"Internal server error"}');
      }
    }
  });
}

async function main() {
  await initCrypto();
  const server = http.createServer(handleRequest);
  server.listen(PORT, HOST, () => {
    log({
      kind: 'ready',
      host: HOST,
      port: PORT,
      hmacEncoding: HMAC_KEY_ENCODING,
      secretSet: SECRET.length > 0,
      saltSet: SALT.length > 0,
      vkLoaded: Boolean(VK),
    });
  });
}

main().catch((error) => {
  console.error(JSON.stringify({ kind: 'fatal', error: error && error.name ? error.name : 'Error' }));
  process.exit(1);
});
