# Steal the VFY agent — Cloudflare Worker plumbing

Single-file Cloudflare Worker implementing the Agent Games "Steal the VFY"
tournament plumbing: HMAC authentication, preflight, turn-envelope validation,
response signing, `publicInputsHash` computation, idempotency, and a dormant
Kurier client. Generated with GPT Astra (via the Xingchi API) from specs
captured read-only from the logged-in Agent Games session on 2026-11-15, then
reviewed and tested locally (62 tests, all passing).

## Status: PLUMBING ONLY — proof module is a STUB

> **Do not enter scored rounds with this code as-is.** Every turn returns a
> schema-valid signed HOLD with no proof fields, because the proof module
> cannot run yet. Per the published score model, an omitted/invalid proof
> costs −2 per turn and a missing/mismatched field is scored as HOLD.
> This harness is ready for preflight + practice dispatch; scored play needs
> the proof module (see Blockers).

What works today:

- HMAC-SHA256 (hex) verification of the raw request body **before** parsing;
  401 on mismatch; every response signed over its exact bytes.
- Preflight: signed `{ok: true, protocolVersion: "v1"}`, HTTP 200.
- Strict turn-envelope validation (protocol version, event id, balances as
  decimal strings, 0x+64-hex commitment hash, nonce presence) with tolerant
  timestamp parsing (ISO-8601 or Unix epoch seconds/ms).
- Exact `publicInputsHash`: keccak256 over ABI-packed 32-byte big-endian
  fields in the published order (commitment, matchId, turn, selfBalance,
  opponentBalance, action enum, amount, circuitVersion "v1" → 1).
- Response schema exactly as captured: `matchId`/`turn` echo, `action`
  (`amount` omitted entirely for HOLD/FORTIFY), `policyProof`
  (`circuitVersion`, `proofReference` only when a real one exists,
  `publicInputsHash`), `agentTimestamp`, deterministic `idempotencyKey`
  (SHA-256 of `matchId:turn`, UUID-shaped, so platform retries of the same
  turn reuse the same key), plus top-level `proof`/`public_signals` only
  when a real proof exists.
- Fail-closed behavior: any error or uncertainty after authentication
  returns a signed schema-valid HOLD; never crashes, never leaks stacks
  or secrets.
- Kurier client (submit + poll to Finalized), dormant unless
  `KURIER_API_KEY` is set **and** a real proof exists. Untested against
  live Kurier.

What is deliberately NOT here:

- **No strategy.** `STRATEGY_PARAMS` is a `null` TODO and `decideAction`
  returns HOLD as a documented safe placeholder (zero cost, no transfer).
  The competitive decision is the owner's; nothing here invents, suggests,
  or hardcodes a heuristic or parameter values.
- **No commitment computation.** `computeStrategyCommitment()` throws.
  The Poseidon preimage layout is unresolved; no formula is guessed.
- **No proof generation.** `generatePolicyProof()` throws
  `ProofNotReadyError`. The intended snarkjs call shape is sketched in
  comments only, with the 17 named circuit inputs mapped in
  `buildCircuitInputs` behind an explicit enablement guard.

## Files

| File | Purpose |
|---|---|
| `worker.js` | The whole agent. No imports, no dependencies. Paste-deployable. |
| `test/worker.test.mjs` | 62 local tests (`node --test`). No network access. |
| `package.json` | ESM marker + `npm test`. No dependencies. |
| `wrangler.toml` | Optional wrangler deploy config. |
| `.env.example` | Env var names. Copy to `.env` locally; never commit `.env`. |

## Deploy

### Option A — Cloudflare dashboard (paste)

1. Cloudflare dashboard → Workers & Pages → Create → Create Worker.
2. Replace the default code with the full contents of `worker.js`. Deploy.
3. Settings → Variables → add secret `AGENT_GAMES_HMAC_SECRET` with the
   one-time value from agent registration / Rotate Secret (see below).
   Save and redeploy/restart the Worker.
4. Note the Worker URL, e.g. `https://steal-the-vfy-agent.<you>.workers.dev`.
   The Worker answers on any path; register the full URL you want the
   platform to POST to (root or `/agent` both work).

### Option B — wrangler CLI

```sh
npx wrangler deploy
npx wrangler secret put AGENT_GAMES_HMAC_SECRET
```

## Register + activate (dashboard — owner actions)

1. Agent Games dashboard → Manage Agents → Register agent.
   - Agent name: your public identifier.
   - Event tracks: Steal the VFY.
   - Repository URL: `https://github.com/Hidayat0703/Zkverify-onlyjepe`
     (this repo; personal account, public).
   - Agent endpoint: your Worker URL from above.
2. **Copy the one-time HMAC secret shown at registration.** It cannot be
   recovered. Set it as `AGENT_GAMES_HMAC_SECRET` in the Worker (above).
   If you rotate the secret later, the old one stops working immediately —
   update the Worker variable first, then rotate, or expect failed
   deliveries in between.
3. Run **preflight** from the dashboard. It must pass (signed preflight
   answered within 10s, HTTP 200, body under 16 KB) before the platform
   marks the agent active.
4. Dashboard → Practice → dispatch the Steal the VFY categories
   (fortify / extract / hold). Practice uses the live delivery path with
   a tighter deadline and no score impact; 10 dispatches per active agent
   per hour. Expect HOLD responses until the proof module is live —
   practice confirms the plumbing, signatures, and deadline behavior.
5. **Strategy commitment (BLOCKED, see below):** Dashboard → My Agents →
   Edit agent → Steal the VFY section, before Swiss Round 1. Requires the
   resolved Poseidon formula. Do not register a guessed hash: the platform
   freezes it at pairing and rejects turns using a different circuit
   version, and a wrong commitment cannot produce valid proofs.
6. Enter the event only after the proof module is live and practice turns
   verify end-to-end.

## Environment variables

| Variable | Required | Purpose |
|---|---|---|
| `AGENT_GAMES_HMAC_SECRET` | Yes | Platform-generated 32-byte HMAC secret, shown once. |
| `STRATEGY_SALT` | Proof module only | Salt for the strategy commitment. Never logged. |
| `KURIER_API_KEY` | No | Kurier mainnet API key. Dormant without a real proof. |

Secrets never appear in logs, responses, or this repo. The worker logs only
`matchId`, `turn`, action type, and error names.

## Strategy knobs (owner fills in)

- `STRATEGY_PARAMS` in `worker.js`: the 8 strategy parameters. TODO.
- `decideAction(state, params)`: must be a pure, deterministic function
  whose output matches the committed circuit exactly. TODO.
- Game constants are exported for the future strategy: `FORTIFY_COST` (2),
  `FORTIFY_BLOCK` (6), `EXTRACT_MAX` (10), `STARTING_BALANCE` (100),
  `TURNS_PER_MATCH` (20).
- The commitment registered on the dashboard must be the Poseidon hash of
  exactly these params + salt, per the formula once resolved. The circuit
  is the referee: any deviation from the committed strategy mid-match is
  rejected.

## Tests

```sh
npm test   # node --test test/worker.test.mjs — 62 tests, no network
```

Covered: keccak256 + HMAC-SHA256 known vectors, public-input packing
(determinism, field-order sensitivity, matchId hyphen handling, rejection
of bad versions/enums/amounts), timestamp parsing, envelope validation
(accept/reject matrix), action normalization (amount stripping), proof-stub
guards, idempotency determinism, response schema (HOLD/EXTRACT/proof
pass-through), dormant Kurier behavior, and end-to-end fetch-handler cases
(valid turn, tampered body, missing/wrong signature, missing secret,
preflight, invalid JSON, wrong event id, GET, expired deadline, unknown
shape, signed error responses).

Caveat: **no official `publicInputsHash` test vector was published**, so the
hash tests are internal-consistency checks (packing layout, determinism,
order sensitivity) plus the keccak primitive vectors — not a
platform-confirmed value. The first practice dispatch is the real
confirmation.

## Will proving fit in a Cloudflare Worker?

Honest answer: **not verified, and likely not on the free tier.**

- Artifacts: `vfy-policy.wasm` 2,991,212 bytes + `vfy-policy_final.zkey`
  810,586 bytes, plus snarkjs. A single-file paste deploy cannot hold them;
  they need wrangler bundling with Workers Assets, R2, or fetch-at-runtime
  from a pinned URL.
- CPU: free tier allows ~10 ms CPU per request — Groth16 proving for a
  ~2k-constraint circuit is far over that. Paid Workers allow 30 s CPU by
  default (extendable), which is plausible but untested for this circuit.
- Worker size limits (~3 MB compressed free / ~10 MB paid) and the 128 MB
  isolate memory cap also constrain the wasm + proving key + snarkjs bundle.

Concrete alternative if Workers cannot fit: run the same handler shape on a
small always-on Node server (Vercel/Node, Fly.io, or a VPS) where snarkjs
loads the artifacts from disk. The proof module is isolated
(`generatePolicyProof` / `buildCircuitInputs`), so only that part moves;
the HMAC/validation/response code is runtime-agnostic. Decide after the
commitment formula is resolved and proving time is measured locally —
do not commit to a host before that.

## Open blockers (do not work around by guessing)

1. **Poseidon commitment preimage layout** — params order, salt position,
   and the circuit's policy semantics / public-private split are unknown
   (wasm disassembly or official disclosure needed). Blocks valid proofs.
2. **HMAC key encoding** — the worker uses the UTF-8 bytes of the secret
   string. Unconfirmed; verify against one real signed practice dispatch.
   If preflight fails with a signature error, this is the first suspect.
3. **Kurier required or not** — unresolved. `/build` calls `proofReference`
   an optional audit pointer, but practice evaluation lists "Policy proof
   transaction confirmed on-chain". The Kurier path exists and is dormant;
   a practice capture decides whether it must run.
4. **`agentTimestamp` format** — unspecified; ISO-8601 assumed.
5. **Nonce policy** — "reject expired nonces" with no published window;
   the worker enforces presence only, so platform retries are not broken.

## Spec sources

Captured read-only from the logged-in session on 2026-11-15 (see
`~/workspace/agentgames/spec-capture/` in the builder's workspace):
`/build` (envelope/response schemas, `publicInputsHash` formula, actions,
preflight, Kurier snippet), the Steal the VFY starter prompt, `/guide`,
`/rules` (tabs 01–03), `/events/steal-the-vfy`, dashboard captures, and
client JS-bundle findings. Circuit artifacts + vk hash via
`/api/circuit-info`. Anything not in those captures is marked
`ASSUMPTION (unconfirmed)` or `TODO` in the code.
