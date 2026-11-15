// test/worker.test.mjs
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import worker, {
  FORTIFY_COST,
  FORTIFY_BLOCK,
  EXTRACT_MAX,
  STARTING_BALANCE,
  TURNS_PER_MATCH,
  SWISS_ROUNDS,
  PROOF_MODULE_STATUS,
  STRATEGY_PARAMS,
  REGISTERED_VK_HASH,
  keccak256,
  hmacSha256Hex,
  constantTimeHexEqual,
  constantTimeBytesEqual,
  bytesToHex,
  packPublicInputs,
  computePublicInputsHash,
  parseTimestamp,
  validateTurnEnvelope,
  normalizeAction,
  decideAction,
  ProofNotReadyError,
  KurierError,
  computeStrategyCommitment,
  buildCircuitInputs,
  generatePolicyProof,
  deriveIdempotencyKey,
  buildTurnResponse,
  submitToKurier,
} from "../worker.js";

const SECRET = "test-secret-do-not-use-in-production";
const encoder = new TextEncoder();
const SIGNATURE_HEADER = "x-agent-games-signature";
const HOLD = 0;
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function fixture() {
  return {
    protocolVersion: "v1",
    eventId: "steal-the-vfy",
    mode: "competition",
    matchId: "9f4e1b2a-0000-4000-8000-000000000000",
    turn: 3,
    issuedAt: "2026-11-15T04:00:00.000Z",
    deadlineAt: "2099-01-01T00:00:00.000Z",
    state: {
      selfBalance: "95",
      opponentBalance: "105",
      selfFortifiedUntilTurn: null,
      opponentFortifiedUntilTurn: null,
    },
    strategyCommitment: {
      hash: "0x7d00000000000000000000000000000000000000000000000000000000000091",
    },
    resolverVersion: "v1",
    nonce: "3c2f1a9e",
  };
}

function fields(overrides = {}) {
  const input = fixture();
  return {
    commitment: input.strategyCommitment.hash,
    matchId: input.matchId,
    turn: input.turn,
    selfBalance: 95n,
    opponentBalance: 105n,
    actionEnum: HOLD,
    amount: 0,
    circuitVersion: "v1",
    ...overrides,
  };
}

// The API does not specify which of enum values 1 and 2 denotes EXTRACT.
// Identify it by the documented positive-amount rule, without choosing
// an undocumented mapping. HOLD uses enum 0.
function extractEnum() {
  const candidates = [1, 2].filter((actionEnum) => {
    try {
      packPublicInputs(fields({ actionEnum, amount: 5 }));
      return true;
    } catch {
      return false;
    }
  });
  assert.equal(candidates.length, 1, "exactly one enum must accept amount 5");
  return candidates[0];
}

function assertAbsent(object, keys) {
  for (const key of keys) {
    assert.equal(Object.hasOwn(object, key), false, `unexpected key: ${key}`);
  }
}

function assertHoldResponse(body) {
  assert.deepEqual(body.action, { type: "HOLD" });
  assertAbsent(body.action, ["amount"]);
  assertAbsent(body, ["proof", "public_signals"]);
  assertAbsent(body.policyProof, ["proofReference", "proof", "public_signals"]);
  assert.equal(body.matchId, fixture().matchId);
  assert.equal(body.turn, fixture().turn);
}

async function signedRequest(rawBody, {
  method = "POST",
  secret = SECRET,
  signature,
} = {}) {
  const headers = new Headers({ "content-type": "application/json" });
  headers.set(
    SIGNATURE_HEADER,
    signature ?? await hmacSha256Hex(secret, encoder.encode(rawBody)),
  );
  return new Request("https://worker.example.invalid/", {
    method,
    headers,
    ...(method === "GET" || method === "HEAD" ? {} : { body: rawBody }),
  });
}

async function invoke(rawBody, options = {}, env = {
  AGENT_GAMES_HMAC_SECRET: SECRET,
}) {
  return worker.fetch(await signedRequest(rawBody, options), env, {});
}

async function signedJson(response, expectedStatus, secret = SECRET) {
  assert.equal(response.status, expectedStatus);
  const bytes = new Uint8Array(await response.arrayBuffer());
  const signature = response.headers.get(SIGNATURE_HEADER);
  assert.match(signature ?? "", /^[0-9a-f]{64}$/i);
  assert.equal(signature, await hmacSha256Hex(secret, bytes));
  return JSON.parse(new TextDecoder().decode(bytes));
}

describe("constants", () => {
  it("exports the documented configuration", () => {
    assert.equal(FORTIFY_COST, 2);
    assert.equal(FORTIFY_BLOCK, 6);
    assert.equal(EXTRACT_MAX, 10);
    assert.equal(STARTING_BALANCE, 100);
    assert.equal(TURNS_PER_MATCH, 20);
    assert.equal(SWISS_ROUNDS, 5);
    assert.equal(PROOF_MODULE_STATUS, "STUB");
    assert.equal(STRATEGY_PARAMS, null);
    assert.equal(
      REGISTERED_VK_HASH,
      "0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047",
    );
  });
});

describe("cryptographic helpers", () => {
  for (const [input, expected] of [
    ["", "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"],
    ["abc", "0x4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"],
    ["hello world", "0x47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad"],
  ]) {
    it(`matches the Keccak-256 vector for ${JSON.stringify(input)}`, () => {
      assert.equal(keccak256(encoder.encode(input)), expected);
    });
  }

  it("handles a 200-byte multi-block Keccak input", () => {
    const bytes = Uint8Array.from({ length: 200 }, (_, i) => i);
    assert.match(keccak256(bytes), /^0x[0-9a-f]{64}$/);
  });

  it("matches the HMAC-SHA256 known vector without a prefix", async () => {
    assert.equal(
      await hmacSha256Hex(
        "key",
        encoder.encode("The quick brown fox jumps over the lazy dog"),
      ),
      "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8",
    );
  });

  it("compares valid hexadecimal strings case-insensitively", () => {
    const hex = "abcdef0123456789".repeat(4);
    assert.equal(constantTimeHexEqual(hex, hex.toUpperCase()), true);
    assert.equal(constantTimeHexEqual(hex, `sha256=${hex}`), true);
    assert.equal(constantTimeHexEqual(`sha256=${hex}`, hex), true);
    assert.equal(constantTimeHexEqual(hex, `0${hex.slice(1)}`), false);
    assert.equal(constantTimeHexEqual(hex, hex.slice(2)), false);
  });

  it("rejects malformed, empty, and null hexadecimal values", () => {
    const valid = "ab".repeat(32);
    for (const invalid of ["", "gg", "not-hex", null]) {
      assert.equal(constantTimeHexEqual(invalid, valid), false);
      assert.equal(constantTimeHexEqual(valid, invalid), false);
      assert.equal(constantTimeHexEqual(invalid, invalid), false);
    }
  });

  it("compares bytes by value and length", () => {
    assert.equal(
      constantTimeBytesEqual(new Uint8Array([0, 1, 255]), new Uint8Array([0, 1, 255])),
      true,
    );
    assert.equal(
      constantTimeBytesEqual(new Uint8Array([0, 1]), new Uint8Array([0, 2])),
      false,
    );
    assert.equal(
      constantTimeBytesEqual(new Uint8Array([0]), new Uint8Array([0, 0])),
      false,
    );
  });

  it("formats bytes as zero-padded hexadecimal", () => {
    assert.equal(bytesToHex(new Uint8Array([0, 1, 15, 16, 128, 255])), "00010f1080ff");
    assert.equal(bytesToHex(new Uint8Array()), "");
  });
});

describe("public input packing and hashing", () => {
  // No official publicInputsHash test vector was published, so these are
  // internal-consistency checks only.
  it("packs eight 32-byte words with commitment first and version last", () => {
    const input = fields();
    const packed = packPublicInputs(input);
    assert.ok(packed instanceof Uint8Array);
    assert.equal(packed.length, 256);
    assert.equal(bytesToHex(packed.slice(0, 32)), input.commitment.slice(2));
    const versionWord = new Uint8Array(32);
    versionWord[31] = 1;
    assert.deepEqual(packed.slice(-32), versionWord);
  });

  it("hashes the packed bytes deterministically", () => {
    const input = fields();
    const hash = computePublicInputsHash(input);
    assert.match(hash, /^0x[0-9a-f]{64}$/);
    assert.equal(hash, computePublicInputsHash({ ...input }));
    assert.equal(hash, keccak256(packPublicInputs(input)));
  });

  it("binds balance order, turn, and action enum", () => {
    const baseline = computePublicInputsHash(fields());
    assert.notEqual(
      baseline,
      computePublicInputsHash(fields({ selfBalance: 105n, opponentBalance: 95n })),
    );
    assert.notEqual(baseline, computePublicInputsHash(fields({ turn: 4 })));
    const fortifyEnum = extractEnum() === 1 ? 2 : 1;
    assert.notEqual(
      baseline,
      computePublicInputsHash(fields({ actionEnum: fortifyEnum })),
    );
  });

  it("ignores matchId hyphens", () => {
    assert.equal(
      computePublicInputsHash(fields()),
      computePublicInputsHash(fields({
        matchId: fixture().matchId.replaceAll("-", ""),
      })),
    );
  });

  it("rejects unsupported versions, invalid enums, and invalid amounts", () => {
    assert.throws(() => packPublicInputs(fields({ circuitVersion: "v2" })));
    assert.throws(() => packPublicInputs(fields({ actionEnum: 3 })));
    assert.throws(() => packPublicInputs(fields({ amount: 5 })));
    const actionEnum = extractEnum();
    for (const amount of [0, 11]) {
      assert.throws(() => packPublicInputs(fields({ actionEnum, amount })));
    }
    const fortifyEnum = actionEnum === 1 ? 2 : 1;
    assert.throws(() =>
      packPublicInputs(fields({ actionEnum: fortifyEnum, amount: 5 })),
    );
  });

  it("accepts both EXTRACT amount boundaries", () => {
    const actionEnum = extractEnum();
    for (const amount of [1, 10]) {
      assert.equal(packPublicInputs(fields({ actionEnum, amount })).length, 256);
    }
  });
});

describe("timestamps and turn validation", () => {
  it("parses ISO strings, epoch seconds, and epoch milliseconds", () => {
    const iso = fixture().issuedAt;
    const ms = Date.parse(iso);
    assert.equal(parseTimestamp(iso), ms);
    assert.equal(parseTimestamp(ms / 1000), ms);
    assert.equal(parseTimestamp(ms), ms);
    assert.equal(parseTimestamp("garbage"), null);
  });

  it("normalizes valid balances, turn, and timestamps", () => {
    const input = fixture();
    const normalized = validateTurnEnvelope(input);
    assert.equal(normalized.state.selfBalance, 95n);
    assert.equal(normalized.state.opponentBalance, 105n);
    assert.equal(normalized.turn, 3);
    assert.equal(typeof normalized.turn, "number");
    assert.equal(normalized.issuedAtMs, Date.parse(input.issuedAt));
    assert.equal(normalized.deadlineAtMs, Date.parse(input.deadlineAt));
  });

  const invalidCases = [
    ["wrong protocolVersion", (x) => { x.protocolVersion = "v2"; }],
    ["wrong eventId", (x) => { x.eventId = "fake-other-event"; }],
    ["missing nonce", (x) => { delete x.nonce; }],
    ["empty matchId", (x) => { x.matchId = ""; }],
    ["non-integer turn", (x) => { x.turn = 3.5; }],
    ["numeric self balance", (x) => { x.state.selfBalance = 95; }],
    ["numeric opponent balance", (x) => { x.state.opponentBalance = 105; }],
    ["malformed self balance", (x) => { x.state.selfBalance = "12x"; }],
    ["malformed opponent balance", (x) => { x.state.opponentBalance = "12x"; }],
    ["short commitment", (x) => { x.strategyCommitment.hash = "0x1234"; }],
    ["commitment without 0x", (x) => {
      x.strategyCommitment.hash = x.strategyCommitment.hash.slice(2);
    }],
    ["missing state", (x) => { delete x.state; }],
    ["missing strategyCommitment", (x) => { delete x.strategyCommitment; }],
    ["missing deadlineAt", (x) => { delete x.deadlineAt; }],
  ];

  for (const [name, mutate] of invalidCases) {
    it(`rejects ${name}`, () => {
      const input = fixture();
      mutate(input);
      assert.throws(() => validateTurnEnvelope(input));
    });
  }

  for (const key of ["selfFortifiedUntilTurn", "opponentFortifiedUntilTurn"]) {
    it(`accepts integer 5 and rejects -1 for ${key}`, () => {
      const input = fixture();
      input.state[key] = 5;
      assert.doesNotThrow(() => validateTurnEnvelope(input));
      input.state[key] = -1;
      assert.throws(() => validateTurnEnvelope(input));
    });
  }

  it("accepts practice mode", () => {
    const input = fixture();
    input.mode = "practice";
    assert.doesNotThrow(() => validateTurnEnvelope(input));
  });
});

describe("actions and proof stubs", () => {
  it("normalizes valid actions and strips irrelevant amounts", () => {
    assert.deepEqual(normalizeAction({ type: "HOLD", amount: 5 }), { type: "HOLD" });
    assert.deepEqual(normalizeAction({ type: "FORTIFY", amount: 5 }), { type: "FORTIFY" });
    assert.deepEqual(normalizeAction({ type: "EXTRACT", amount: 5 }), {
      type: "EXTRACT",
      amount: 5,
    });
  });

  it("falls back to HOLD for invalid actions", () => {
    for (const action of [
      { type: "EXTRACT", amount: 0 },
      { type: "EXTRACT", amount: 11 },
      { type: "UNKNOWN" },
      null,
      undefined,
      "EXTRACT",
      5,
    ]) {
      assert.deepEqual(normalizeAction(action), { type: "HOLD" });
    }
  });

  it("uses the safe HOLD strategy placeholder", () => {
    assert.deepEqual(
      decideAction(validateTurnEnvelope(fixture()), STRATEGY_PARAMS),
      { type: "HOLD" },
    );
  });

  it("exports Error subclasses", () => {
    assert.ok(ProofNotReadyError.prototype instanceof Error);
    assert.ok(KurierError.prototype instanceof Error);
  });

  it("refuses to compute a stub strategy commitment", () => {
    assert.throws(() => computeStrategyCommitment(), ProofNotReadyError);
  });

  it("rejects policy proof generation", async () => {
    await assert.rejects(
      async () => generatePolicyProof(
        validateTurnEnvelope(fixture()),
        { type: "HOLD" },
        {
          commitment: fixture().strategyCommitment.hash,
          salt: "fake-test-salt",
          strategyParams: STRATEGY_PARAMS,
        },
      ),
      ProofNotReadyError,
    );
  });

  it("requires explicit enablement to build circuit inputs", () => {
    const envelope = validateTurnEnvelope(fixture());
    const config = {
      commitment: fixture().strategyCommitment.hash,
      salt: "fake-test-salt",
      strategyParams: STRATEGY_PARAMS,
    };
    for (const options of [{}, { explicitlyEnabled: false }]) {
      assert.throws(
        () => buildCircuitInputs(envelope, { type: "HOLD" }, config, options),
        ProofNotReadyError,
      );
    }
  });
});

describe("idempotency keys and turn responses", () => {
  it("derives stable UUID-shaped keys that change with turn", async () => {
    const { matchId, turn } = fixture();
    const first = await deriveIdempotencyKey(matchId, turn);
    assert.match(first, UUID_PATTERN);
    assert.equal(first, await deriveIdempotencyKey(matchId, turn));
    assert.notEqual(first, await deriveIdempotencyKey(matchId, turn + 1));
  });

  it("builds a HOLD response without proof or amount fields", async () => {
    const envelope = validateTurnEnvelope(fixture());
    const body = await buildTurnResponse(envelope, { type: "HOLD" }, {});
    assertHoldResponse(body);
    assert.equal(body.policyProof.circuitVersion, "v1");
    assert.equal(
      body.policyProof.publicInputsHash,
      computePublicInputsHash(fields()),
    );
    assert.deepEqual(Object.keys(body.policyProof), [
      "circuitVersion",
      "publicInputsHash",
    ]);
    assert.equal(typeof body.agentTimestamp, "string");
    assert.ok(Number.isFinite(Date.parse(body.agentTimestamp)));
    assert.equal(
      body.idempotencyKey,
      await deriveIdempotencyKey(envelope.matchId, envelope.turn),
    );
  });

  it("includes EXTRACT amount and binds it into the public input hash", async () => {
    const envelope = validateTurnEnvelope(fixture());
    const hold = await buildTurnResponse(envelope, { type: "HOLD" }, {});
    const extract = await buildTurnResponse(
      envelope,
      { type: "EXTRACT", amount: 5 },
      {},
    );
    assert.deepEqual(extract.action, { type: "EXTRACT", amount: 5 });
    assert.notEqual(
      extract.policyProof.publicInputsHash,
      hold.policyProof.publicInputsHash,
    );
    assert.equal(
      extract.policyProof.publicInputsHash,
      computePublicInputsHash(fields({ actionEnum: extractEnum(), amount: 5 })),
    );
  });

  it("passes supplied fake proof data through without submitting it", async () => {
    const proof = { fake: true, marker: "not-a-real-proof" };
    const publicSignals = ["fake-public-signal"];
    const proofReference = "fake-proof-reference";
    const body = await buildTurnResponse(
      validateTurnEnvelope(fixture()),
      { type: "HOLD" },
      { proof, publicSignals, proofReference },
    );
    assert.deepEqual(body.proof, proof);
    assert.deepEqual(body.public_signals, publicSignals);
    assert.equal(body.policyProof.proofReference, proofReference);
    assert.deepEqual(Object.keys(body.policyProof), [
      "circuitVersion",
      "proofReference",
      "publicInputsHash",
    ]);
  });
});

describe("dormant Kurier submission", () => {
  it("returns undefined without an API key", async () => {
    assert.equal(await submitToKurier({
      proof: { fake: true, marker: "not-a-real-proof" },
      publicSignals: [],
      deadlineAtMs: Date.parse(fixture().deadlineAt),
    }), undefined);
  });

  it("returns undefined with a fake key but no proof", async () => {
    assert.equal(await submitToKurier({
      apiKey: "fake-kurier-key-not-valid",
      publicSignals: [],
      deadlineAtMs: Date.parse(fixture().deadlineAt),
    }), undefined);
  });
});

describe("fetch handler", () => {
  it("returns signed HOLD responses with stable idempotency keys", async () => {
    const raw = JSON.stringify(fixture());
    const first = await signedJson(await invoke(raw), 200);
    const second = await signedJson(await invoke(raw), 200);
    assertHoldResponse(first);
    assertHoldResponse(second);
    assert.equal(first.idempotencyKey, second.idempotencyKey);
    assert.equal(
      first.idempotencyKey,
      await deriveIdempotencyKey(fixture().matchId, fixture().turn),
    );
  });

  it("rejects a body changed by one byte after signing", async () => {
    const original = JSON.stringify(fixture());
    const signature = await hmacSha256Hex(SECRET, encoder.encode(original));
    const tampered = original.replace('"turn":3', '"turn":4');
    assert.notEqual(tampered, original);
    await signedJson(await invoke(tampered, { signature }), 401);
  });

  it("rejects missing signatures", async () => {
    const request = new Request("https://worker.example.invalid/", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(fixture()),
    });
    await signedJson(
      await worker.fetch(request, { AGENT_GAMES_HMAC_SECRET: SECRET }, {}),
      401,
    );
  });

  it("rejects signatures made with another fake secret", async () => {
    await signedJson(await invoke(JSON.stringify(fixture()), {
      secret: "fake-wrong-test-secret",
    }), 401);
  });

  for (const [label, env] of [
    ["missing", {}],
    ["empty", { AGENT_GAMES_HMAC_SECRET: "" }],
  ]) {
    it(`returns 500 for a ${label} HMAC secret`, async () => {
      const response = await invoke(JSON.stringify(fixture()), {}, env);
      assert.equal(response.status, 500);
      // No configured secret exists with which to verify this error response.
    });
  }

  function preflight() {
    return {
      type: "agent-games.preflight.v1",
      agent_id: "fake-test-agent",
      issued_at: fixture().issuedAt,
      nonce: "fake-preflight-nonce",
    };
  }

  it("returns the signed preflight acknowledgement", async () => {
    assert.deepEqual(
      await signedJson(await invoke(JSON.stringify(preflight())), 200),
      { ok: true, protocolVersion: "v1" },
    );
  });

  it("rejects preflight with a bad signature", async () => {
    await signedJson(
      await invoke(JSON.stringify(preflight()), { signature: "00".repeat(32) }),
      401,
    );
  });

  it("returns signed 400 for correctly signed invalid JSON", async () => {
    await signedJson(await invoke('{"invalid":'), 400);
  });

  it("authenticates raw bytes before attempting JSON parsing", async () => {
    await signedJson(
      await invoke('{"invalid":', { signature: "00".repeat(32) }),
      401,
    );
  });

  it("returns signed 400 for a wrong eventId", async () => {
    const input = fixture();
    input.eventId = "fake-other-event";
    await signedJson(await invoke(JSON.stringify(input)), 400);
  });

  it("returns signed 400 for GET with a valid empty-body signature", async () => {
    await signedJson(await invoke("", { method: "GET" }), 400);
  });

  it("returns signed HOLD for an expired deadline", async () => {
    const input = fixture();
    input.issuedAt = "2000-01-01T00:00:00.000Z";
    input.deadlineAt = "2000-01-01T00:01:00.000Z";
    const body = await signedJson(await invoke(JSON.stringify(input)), 200);
    assertHoldResponse(body);
  });

  it("returns signed 400 for an unknown JSON shape", async () => {
    await signedJson(await invoke("{}"), 400);
  });
});
