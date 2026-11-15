/**
 * Single-file Cloudflare Worker: zkVerify Agent Games / Steal the VFY plumbing.
 * Source: the user-supplied captured turn, authentication, circuit, and /build specs.
 * PROOF STATUS: STUB; decisions are a safe HOLD placeholder, not a strategy.
 * Env: AGENT_GAMES_HMAC_SECRET (required), STRATEGY_SALT (proof path only),
 *      KURIER_API_KEY (optional; dormant without a real proof).
 * Open blockers: Poseidon commitment formula/preimage, circuit policy and signal
 * visibility, HMAC key encoding, whether Kurier submission is required.
 * Kurier integration is UNTESTED against live Kurier.
 */

export const FORTIFY_COST = 2;
export const FORTIFY_BLOCK = 6;
export const EXTRACT_MAX = 10;
export const STARTING_BALANCE = 100;
export const TURNS_PER_MATCH = 20;
export const SWISS_ROUNDS = 5;
export const PROOF_MODULE_STATUS = "STUB";

// TODO: The user supplies their own eight strategy parameters.
// Nothing in this module implements a strategy.
export const STRATEGY_PARAMS = null;

export const REGISTERED_VK_HASH =
  "0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047";

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

function utf8(value) {
  return new TextEncoder().encode(value);
}

function requireBytes(bytes) {
  if (!(bytes instanceof Uint8Array)) {
    throw new TypeError("Expected Uint8Array");
  }
  return bytes;
}

export function bytesToHex(bytes) {
  return Array.from(requireBytes(bytes), b => b.toString(16).padStart(2, "0")).join("");
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

/** Keccak-256, with Keccak's 0x01 domain suffix (not SHA3's 0x06). */
export function keccak256(bytes) {
  requireBytes(bytes);
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

export async function hmacSha256Hex(secretString, bytes) {
  if (typeof secretString !== "string" || secretString.length === 0) {
    throw new Error("HMAC key unavailable");
  }
  // ASSUMPTION (unconfirmed): use UTF-8 bytes of the secret string, not hex decoding.
  const key = await crypto.subtle.importKey(
    "raw",
    utf8(secretString),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign("HMAC", key, requireBytes(bytes));
  return bytesToHex(new Uint8Array(signature));
}

/**
 * No content-dependent early exit; length is public.
 * JavaScript runtimes do not guarantee machine-level constant-time execution.
 */
export function constantTimeBytesEqual(a, b) {
  requireBytes(a);
  requireBytes(b);
  let difference = a.length ^ b.length;
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    difference |= (a[i] ?? 0) ^ (b[i] ?? 0);
  }
  return difference === 0;
}

function decodeSignature(value) {
  // Defensive tolerance, not spec: accept an optional "sha256=" prefix.
  const text = typeof value === "string" ? value.replace(/^sha256=/i, "") : "";
  const valid = /^[a-fA-F0-9]{64}$/.test(text);
  const bytes = new Uint8Array(32);
  if (valid) {
    for (let i = 0; i < 32; i++) {
      bytes[i] = Number.parseInt(text.slice(i * 2, i * 2 + 2), 16);
    }
  }
  return { bytes, valid };
}

export function constantTimeHexEqual(left, right) {
  const a = decodeSignature(left);
  const b = decodeSignature(right);
  const equal = constantTimeBytesEqual(a.bytes, b.bytes);
  return Boolean(Number(equal) & Number(a.valid) & Number(b.valid));
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function nonEmptyString(value, name) {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new Error(`${name} must be a non-empty string`);
  }
  return value;
}

function turnNumber(value, name) {
  // Implementation decision: reject integers JS cannot represent exactly.
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`${name} must be a non-negative safe integer`);
  }
  return value;
}

function uint256(value, name) {
  let n;
  if (typeof value === "bigint") {
    n = value;
  } else if (typeof value === "number" && Number.isSafeInteger(value)) {
    n = BigInt(value);
  } else if (typeof value === "string" && /^\d+$/.test(value)) {
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
  if (typeof value !== "string" || !/^\d+$/.test(value)) {
    throw new Error(`${name} must be a decimal string`);
  }
  return uint256(value, name);
}

function commitmentValue(value) {
  if (typeof value !== "string" || !/^0x[a-fA-F0-9]{64}$/.test(value)) {
    throw new Error("strategyCommitment.hash must be a 32-byte 0x hash");
  }
  return BigInt(value);
}

function matchIdValue(matchId) {
  nonEmptyString(matchId, "matchId");
  const hex = matchId.replace(/-/g, "");
  if (!/^[a-fA-F0-9]{1,64}$/.test(hex)) {
    throw new Error("matchId must encode at most 32 bytes of hexadecimal");
  }
  return BigInt(`0x${hex}`);
}

/** Eight 32-byte, big-endian words, in the captured protocol order. */
export function packPublicInputs({
  commitment, matchId, turn, selfBalance, opponentBalance,
  actionEnum, amount, circuitVersion,
}) {
  if (circuitVersion !== "v1") throw new Error("Unsupported circuitVersion");
  const action = uint256(actionEnum, "actionEnum");
  const quantity = uint256(amount, "amount");
  if (action > 2n) throw new Error("Invalid action enum");
  if (
    (action === 2n && (quantity < 1n || quantity > 10n)) ||
    (action !== 2n && quantity !== 0n)
  ) {
    throw new Error("Invalid action amount");
  }
  const words = [
    commitmentValue(commitment),
    matchIdValue(matchId),
    uint256(turn, "turn"),
    uint256(selfBalance, "selfBalance"),
    uint256(opponentBalance, "opponentBalance"),
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

export function computePublicInputsHash(fields) {
  return keccak256(packPublicInputs(fields));
}

/** Unparseable timestamps remain null; their presence is still required. */
export function parseTimestamp(value) {
  if (typeof value === "number" && Number.isFinite(value)) {
    // ASSUMPTION (unconfirmed): magnitudes below 1e11 are epoch seconds.
    // Seconds versus milliseconds cannot be distinguished without a convention.
    const ms = Math.abs(value) < 1e11 ? value * 1000 : value;
    return Number.isFinite(new Date(ms).getTime()) ? ms : null;
  }
  if (typeof value === "string") {
    const ms = Date.parse(value);
    return Number.isFinite(ms) ? ms : null;
  }
  return null;
}

function requireNonce(value) {
  // ASSUMPTION (unconfirmed): presence only; no undocumented expiry window
  // and no replay rejection, because the platform may retry.
  return nonEmptyString(value, "nonce");
}

export function validateTurnEnvelope(obj) {
  if (!isRecord(obj)) throw new Error("Envelope must be an object");
  if (obj.protocolVersion !== "v1") throw new Error("Invalid protocolVersion");
  if (obj.eventId !== "steal-the-vfy") throw new Error("Invalid eventId");
  const matchId = nonEmptyString(obj.matchId, "matchId");
  const turn = turnNumber(obj.turn, "turn");
  if (typeof obj.mode !== "string") throw new Error("mode must be a string");
  for (const field of ["resolverVersion", "issuedAt", "deadlineAt"]) {
    if (!Object.hasOwn(obj, field)) throw new Error(`${field} is required`);
  }
  if (!isRecord(obj.state)) throw new Error("state is required");
  if (!isRecord(obj.strategyCommitment)) {
    throw new Error("strategyCommitment is required");
  }
  commitmentValue(obj.strategyCommitment.hash);
  const fortified = (value, name) =>
    value === null ? null : turnNumber(value, name);

  return {
    protocolVersion: obj.protocolVersion,
    eventId: obj.eventId,
    mode: obj.mode,
    matchId,
    turn,
    issuedAt: obj.issuedAt,
    deadlineAt: obj.deadlineAt,
    state: {
      selfBalance: balance(obj.state.selfBalance, "selfBalance"),
      opponentBalance: balance(obj.state.opponentBalance, "opponentBalance"),
      selfFortifiedUntilTurn: fortified(
        obj.state.selfFortifiedUntilTurn, "selfFortifiedUntilTurn",
      ),
      opponentFortifiedUntilTurn: fortified(
        obj.state.opponentFortifiedUntilTurn, "opponentFortifiedUntilTurn",
      ),
    },
    strategyCommitment: { hash: obj.strategyCommitment.hash },
    resolverVersion: obj.resolverVersion,
    nonce: requireNonce(obj.nonce),
    issuedAtMs: parseTimestamp(obj.issuedAt),
    deadlineAtMs: parseTimestamp(obj.deadlineAt),
  };
}

export function normalizeAction(action) {
  if (!isRecord(action)) return { type: "HOLD" };
  if (action.type === "HOLD" || action.type === "FORTIFY") {
    return { type: action.type };
  }
  if (
    action.type === "EXTRACT" &&
    Number.isInteger(action.amount) &&
    action.amount >= 1 &&
    action.amount <= EXTRACT_MAX
  ) {
    return { type: "EXTRACT", amount: action.amount };
  }
  return { type: "HOLD" };
}

function actionFields(action) {
  const normalized = normalizeAction(action);
  return {
    actionEnum: { HOLD: 0, FORTIFY: 1, EXTRACT: 2 }[normalized.type],
    amount: normalized.type === "EXTRACT" ? normalized.amount : 0,
  };
}

export function decideAction(normalizedEnvelope, strategyParams) {
  // TODO: User implements their own decision function.
  // SAFE PLACEHOLDER ONLY: zero cost, no transfer.
  return { type: "HOLD" };
}

export class ProofNotReadyError extends Error {
  constructor(message) {
    super(message);
    this.name = "ProofNotReadyError";
  }
}

export function computeStrategyCommitment() {
  // TODO: Obtain the authoritative Poseidon formula and preimage layout.
  throw new ProofNotReadyError("Poseidon commitment formula unresolved");
}

export function buildCircuitInputs(
  normalizedEnvelope,
  action,
  { commitment, salt, strategyParams },
  { explicitlyEnabled = false } = {},
) {
  if (!explicitlyEnabled) {
    throw new ProofNotReadyError("Circuit input mapping requires explicit enablement");
  }
  // TODO: Confirm encodings, policy semantics, and public/private signal split.
  // This mapping alone neither computes nor verifies the strategy commitment.
  if (!Array.isArray(strategyParams) || strategyParams.length !== 8) {
    throw new ProofNotReadyError("Eight user-supplied strategy parameters required");
  }
  if (typeof salt !== "string" || salt.length === 0) {
    throw new ProofNotReadyError("Strategy salt is required");
  }
  const fields = actionFields(action);
  return {
    action: String(fields.actionEnum),
    amount: String(fields.amount),
    circuitVersion: "1",
    // ASSUMPTION (unconfirmed): decimal scalar strings are accepted by the circuit.
    commitment: commitmentValue(commitment).toString(),
    // ASSUMPTION (unconfirmed): circuit matchId is UUID-stripped hexadecimal BigInt.
    matchId: matchIdValue(normalizedEnvelope.matchId).toString(),
    opponentBalance: normalizedEnvelope.state.opponentBalance.toString(),
    // TODO: Confirm salt encoding; pass STRATEGY_SALT through without guessing.
    salt,
    selfBalance: normalizedEnvelope.state.selfBalance.toString(),
    // TODO: Confirm parameter encodings; source is the user's STRATEGY_PARAMS.
    strategyParams: strategyParams.slice(),
    turnNumber: String(normalizedEnvelope.turn),
  };
}

export async function generatePolicyProof(normalizedEnvelope, action, options) {
  // TODO: Implement only after commitment layout and circuit semantics are known.
  // NOT IMPLEMENTED: intended external-prover/snarkjs call shape:
  //
  // const inputs = buildCircuitInputs(normalizedEnvelope, action, options,
  //   { explicitlyEnabled: true });
  // const wasm = new Uint8Array(await (await fetch(confirmedWasmUrl)).arrayBuffer());
  // const zkey = new Uint8Array(await (await fetch(confirmedZkeyUrl)).arrayBuffer());
  // const { proof, publicSignals } =
  //   await snarkjs.groth16.fullProve(inputs, wasm, zkey);
  // return { proof, publicSignals };
  //
  // TODO: Obtain confirmed artifact URLs from /build and a Worker-compatible
  // prover integration; snarkjs is deliberately neither imported nor available.
  // Artifacts: vfy-policy.wasm (2,991,212 bytes),
  //            vfy-policy_final.zkey (810,586 bytes).
  // Groth16 / BN128, Circom 2.x; 9 scalar signals + strategyParams[8] = 17.
  throw new ProofNotReadyError(
    "proof module is a stub: Poseidon commitment formula unresolved",
  );
}

export async function deriveIdempotencyKey(matchId, turn) {
  nonEmptyString(matchId, "matchId");
  turnNumber(turn, "turn");
  // Implementation decision: SHA-256("matchId:turn"), first 16 bytes,
  // formatted 8-4-4-4-12. Do not overwrite digest bits with UUID version bits.
  const digest = await crypto.subtle.digest("SHA-256", utf8(`${matchId}:${turn}`));
  const hex = bytesToHex(new Uint8Array(digest).subarray(0, 16));
  return [
    hex.slice(0, 8), hex.slice(8, 12), hex.slice(12, 16),
    hex.slice(16, 20), hex.slice(20, 32),
  ].join("-");
}

function hasProof(proof, publicSignals) {
  // Structural gate only, not cryptographic verification. The caller must supply
  // actual prover output; the stub never supplies any.
  return isRecord(proof) && Object.keys(proof).length > 0 &&
    Array.isArray(publicSignals);
}

function hashForAction(envelope, action) {
  return computePublicInputsHash({
    commitment: envelope.strategyCommitment.hash,
    matchId: envelope.matchId,
    turn: envelope.turn,
    selfBalance: envelope.state.selfBalance,
    opponentBalance: envelope.state.opponentBalance,
    ...actionFields(action),
    circuitVersion: "v1",
  });
}

export async function buildTurnResponse(
  normalizedEnvelope,
  action,
  { proof, publicSignals, proofReference } = {},
) {
  const normalized = normalizeAction(action);
  const realProof = hasProof(proof, publicSignals);
  const policyProof = { circuitVersion: "v1" };
  // Preserve the captured policyProof field order when a pointer exists.
  if (realProof && typeof proofReference === "string" && proofReference.length > 0) {
    policyProof.proofReference = proofReference;
  }
  policyProof.publicInputsHash = hashForAction(normalizedEnvelope, normalized);

  const response = {
    matchId: normalizedEnvelope.matchId,
    turn: normalizedEnvelope.turn,
    action: normalized,
    policyProof,
    // ASSUMPTION (unconfirmed): agentTimestamp uses ISO-8601.
    agentTimestamp: new Date().toISOString(),
    idempotencyKey: await deriveIdempotencyKey(
      normalizedEnvelope.matchId, normalizedEnvelope.turn,
    ),
  };
  if (realProof) {
    response.proof = proof;
    response.public_signals = publicSignals;
  }
  return response;
}

export class KurierError extends Error {
  constructor() {
    // Never expose underlying fetch errors: their text may contain the API key.
    super("Kurier submission failed");
    this.name = "KurierError";
  }
}

// Implementation decision: bounded wall-clock budget, including network requests.
const KURIER_TIMEOUT_MS = 30_000;
const KURIER_POLL_MS = 5_000;

export async function submitToKurier({
  apiKey, proof, publicSignals, deadlineAtMs = null,
}) {
  if (typeof apiKey !== "string" || apiKey.length === 0 ||
      !hasProof(proof, publicSignals)) {
    return undefined;
  }
  // UNTESTED against live Kurier.
  const end = Math.min(
    Date.now() + KURIER_TIMEOUT_MS,
    deadlineAtMs === null ? Infinity : deadlineAtMs,
  );
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), Math.max(0, end - Date.now()));

  async function requestJson(url, options = {}) {
    if (Date.now() >= end) throw new KurierError();
    const response = await fetch(url, {
      ...options,
      signal: controller.signal,
      // Implementation decision: do not forward a key-bearing URL via redirects.
      redirect: "error",
    });
    if (!response.ok) throw new KurierError();
    return response.json();
  }

  try {
    const base = "https://api.kurier.xyz/api/v1";
    const encodedKey = encodeURIComponent(apiKey);
    const submitted = await requestJson(`${base}/submit-proof/${encodedKey}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        proofType: "groth16",
        vkRegistered: true,
        proofOptions: { library: "snarkjs", curve: "bn128" },
        proofData: { proof, publicSignals, vk: REGISTERED_VK_HASH },
      }),
    });
    // ASSUMPTION (unconfirmed): jobId and status are top-level response fields.
    // TODO: Confirm the Kurier response envelopes against the live /build snippet.
    if (!isRecord(submitted) ||
        typeof submitted.jobId !== "string" || submitted.jobId.length === 0) {
      throw new KurierError();
    }
    while (Date.now() < end) {
      const remaining = end - Date.now();
      if (remaining <= KURIER_POLL_MS) throw new KurierError();
      await new Promise(resolve => setTimeout(resolve, KURIER_POLL_MS));
      const job = await requestJson(
        `${base}/job-status/${encodedKey}/${encodeURIComponent(submitted.jobId)}`,
      );
      if (isRecord(job) && job.status === "Finalized") {
        // TODO: Confirm the audit-pointer response field and encoding.
        // Finalization alone is not a proofReference; never invent a pointer.
        return { finalized: true };
      }
      // No other terminal status names are specified; the bounded timeout handles
      // all non-Finalized results without guessing protocol status values.
    }
    throw new KurierError();
  } catch {
    throw new KurierError();
  } finally {
    clearTimeout(timer);
  }
}

async function jsonResponse(body, status, secret) {
  const bytes = utf8(JSON.stringify(body));
  const headers = { "content-type": "application/json" };
  if (secret) {
    headers["x-agent-games-signature"] = await hmacSha256Hex(secret, bytes);
  }
  return new Response(bytes, { status, headers });
}

function warnForTurn(envelope, error) {
  // Only the allowed fields are logged; never log error messages or objects.
  const name = error instanceof ProofNotReadyError ? "ProofNotReadyError" :
    error instanceof KurierError ? "KurierError" : "Error";
  console.warn(JSON.stringify({
    matchId: envelope.matchId,
    turn: envelope.turn,
    action: "HOLD",
    error: name,
  }));
}

function validatePreflight(obj) {
  nonEmptyString(obj.agent_id, "agent_id");
  if (!Object.hasOwn(obj, "issued_at")) throw new Error("issued_at is required");
  requireNonce(obj.nonce);
}

async function processTurn(envelope, env) {
  // A parsed, expired deadline is not a rejection: return HOLD immediately,
  // without attempting proof generation or network submission.
  if (envelope.deadlineAtMs !== null && envelope.deadlineAtMs <= Date.now()) {
    return buildTurnResponse(envelope, { type: "HOLD" });
  }

  let action = normalizeAction(decideAction(envelope, STRATEGY_PARAMS));
  let evidence = {};
  try {
    // Required ordering: compute the hash before any zkVerify submission.
    hashForAction(envelope, action);
    const generated = await generatePolicyProof(envelope, action, {
      commitment: envelope.strategyCommitment.hash,
      salt: env.STRATEGY_SALT,
      strategyParams: STRATEGY_PARAMS,
    });
    if (!hasProof(generated?.proof, generated?.publicSignals)) {
      throw new ProofNotReadyError("No real proof was produced");
    }
    evidence = {
      proof: generated.proof,
      publicSignals: generated.publicSignals,
    };
    const submission = await submitToKurier({
      apiKey: env.KURIER_API_KEY,
      ...evidence,
      deadlineAtMs: envelope.deadlineAtMs,
    });
    if (submission?.proofReference) {
      evidence.proofReference = submission.proofReference;
    }
  } catch (error) {
    warnForTurn(envelope, error);
    action = { type: "HOLD" };
    evidence = {};
  }
  return buildTurnResponse(envelope, action, evidence);
}

export default {
  async fetch(request, env, ctx) {
    let secret;
    let rawObject;
    let envelope;
    let authenticated = false;

    try {
      secret = env?.AGENT_GAMES_HMAC_SECRET;
      if (typeof secret !== "string" || secret.length === 0) {
        // Signing is impossible without a key; fail closed with a generic 500.
        return await jsonResponse({ error: "Internal server error" }, 500);
      }

      // Read the original bytes; never parse or reserialize before verification.
      const rawBytes = new Uint8Array(await request.arrayBuffer());
      const expected = await hmacSha256Hex(secret, rawBytes);
      if (!constantTimeHexEqual(
        expected, request.headers.get("x-agent-games-signature"),
      )) {
        return await jsonResponse({ error: "Unauthorized" }, 401, secret);
      }
      authenticated = true;

      // The captured protocol supplies POST envelopes.
      if (request.method !== "POST") {
        return await jsonResponse({ error: "Bad request" }, 400, secret);
      }

      try {
        rawObject = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(rawBytes));
      } catch {
        return await jsonResponse({ error: "Bad request" }, 400, secret);
      }

      if (isRecord(rawObject) && rawObject.type === "agent-games.preflight.v1") {
        try {
          validatePreflight(rawObject);
        } catch {
          return await jsonResponse({ error: "Bad request" }, 400, secret);
        }
        return await jsonResponse({ ok: true, protocolVersion: "v1" }, 200, secret);
      }

      try {
        envelope = validateTurnEnvelope(rawObject);
        // Non-empty matchId is the envelope rule. Its hexadecimal encoding is
        // additionally necessary to produce the required publicInputsHash.
        hashForAction(envelope, { type: "HOLD" });
      } catch {
        return await jsonResponse({ error: "Bad request" }, 400, secret);
      }

      return await jsonResponse(await processTurn(envelope, env), 200, secret);
    } catch {
      // Catch-all: recover a schema-valid HOLD whenever its required inputs exist.
      if (authenticated) {
        try {
          envelope = envelope ?? validateTurnEnvelope(rawObject);
          const hold = await buildTurnResponse(envelope, { type: "HOLD" });
          warnForTurn(envelope, new Error());
          return await jsonResponse(hold, 200, secret);
        } catch {
          // TODO: Clarify recovery when only matchId/turn survive. A valid
          // publicInputsHash also requires commitment and both balances;
          // fabricating those would violate the captured spec.
        }
      }
      try {
        return await jsonResponse(
          { error: authenticated ? "Bad request" : "Internal server error" },
          authenticated ? 400 : 500,
          secret,
        );
      } catch {
        // No valid signature can be produced if Web Crypto/signing itself fails.
        // Fail closed; never return an unsigned successful turn response.
        return new Response('{"error":"Internal server error"}', {
          status: 500,
          headers: { "content-type": "application/json" },
        });
      }
    }
  },
};
