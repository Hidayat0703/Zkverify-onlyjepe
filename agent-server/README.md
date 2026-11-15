# takanome-steal-vfy agent (box-hosted)

Node.js HTTP agent for the zkVerify Agent Games **Steal the VFY** event.
It serves signed turn envelopes, evaluates the committed circuit policy
off-chain, generates a local Groth16 proof with snarkjs, and returns the
union response schema (action + policyProof + proof + public_signals).

## How it runs

The agent binds `127.0.0.1:3123` on a cloud desktop (Simular Box) and is
exposed publicly over HTTPS through an SSH reverse tunnel (serveo). The
registered endpoint is the tunnel URL plus `/agent` (the server answers on
any path). The tunnel URL is random per connection: if the SSH connection
drops, the URL changes and the endpoint must be re-registered on the
dashboard. The host sleeps when idle, so the tunnel + server need a
keep-alive/watch during live rounds.

## Files

- `server.js` — the agent: HMAC-SHA256 verification over the raw body,
  preflight, envelope validation, policy evaluation, snarkjs proving with
  local verification, publicInputsHash (keccak256, ABI-packed), signed
  responses, fail-closed HOLD. No Kurier submission: no `proofReference`
  is emitted.
- `scripts/setup-env.js` — generates `.env` (mode 600) with a fresh random
  salt. Never prints secret values.
- `scripts/commitment.js` — prints only the `COMMITMENT_HASH=0x…` value for
  dashboard registration.
- `scripts/test-local.js` — end-to-end tests on port 3124 (preflight,
  EXTRACT/FORTIFY/HOLD branches with proof verification, auth failures,
  expired deadline).
- `vfy-policy.wasm`, `vfy-policy_final.zkey` — circuit artifacts, downloaded
  from `https://agentgames.zkverify.io/circuits/` (not committed here;
  present on the host next to `server.js`).

## Environment (.env, mode 600, never committed)

See `.env.example`. `AGENT_GAMES_HMAC_SECRET` comes from the platform
(registration panel / Rotate Secret, shown once). `HMAC_KEY_ENCODING`
defaults to `utf8` (UTF-8 bytes of the secret string); `hex` uses
hex-decoded secret bytes (fallback if preflight fails on signature).

## Strategy

Params are `[10, 50, 50, 0, 0, 0, 0, 0]` (EXTRACT 10; FORTIFY when own
balance is below 50; EXTRACT when the opponent is above 50; extraction
enabled). The circuit policy is:

```
FORTIFY if selfBalance < params[1]
else EXTRACT (amount params[0]) if opponentBalance > params[2] and params[3]==0
else HOLD
```

Commitment: `Poseidon(params[0..7], salt)`, salt last, rendered as
`0x` + 64 hex chars. See `circuit-analysis/FINDINGS.md` in the workspace
for the proven formula and public/private signal split.

## Operate

```sh
node scripts/setup-env.js     # first run only; then set the real HMAC secret in .env
node scripts/commitment.js    # register the printed hash on the dashboard
node scripts/test-local.js    # all tests must pass before going public
node server.js                # binds 127.0.0.1:3123
```
