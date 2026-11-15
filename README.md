# 🛡 Sentinel — wallet & transaction guard

Agent Games Wildcard entry (zkVerify Agent Games, closes 21 Nov 2026).
A Cloudflare Workers agent that answers one question before you sign
anything: **"is this contract safe, and prove it?"**

## The problem

Crypto users — airdrop hunters especially — sign blind approvals every
day. One unlimited `approve` to a malicious contract can drain an entire
token balance. Real case: the **Mars Nexus** drain (Nov 2026), where 33
agent wallets were drained after connecting to a site. Existing tools
(explorers, audit PDFs) don't answer the simple pre-signing question with
evidence you can re-check.

## What Sentinel does

Give it a contract address (and optionally the calldata you are about to
sign). It checks the contract **live on-chain** and returns a verdict —
`SAFE` / `CAUTION` / `DANGER` — with a risk score and one evidence-backed
result per check. Every check cites its source (RPC method / public API)
and the block number, so anyone can reproduce the verdict.

### Checks

| # | Check | How | Effect on score |
|---|-------|-----|-----------------|
| 1 | Contract vs EOA | `eth_getCode` | EOA → info only, no audit needed |
| 2 | Reputation | Curated confirmed-scam registry (`KNOWN_SCAMS` in `src/index.js`) | Registry hit: +70, critical |
| 3 | Source verified | Sourcify API **v2** (`/v2/contract/{chainId}/{address}`) | Unverified: +25, never SAFE |
| 4 | Owner | `eth_call` `owner()` | Active owner: +15 |
| 5 | Proxy | `eth_getStorageAt` EIP-1967 slot `0x3608…82bbc` | Proxy: +10 (+10 more if owner active) |
| 6 | Selectors | PUSH4 scan of runtime bytecode (PUSH-aware, metadata trailer stripped), names via 4byte.directory | `selfdestruct`/`delegatecall`: +40 critical; `withdraw`/`sweep`: +15; `mint`: +10; fee/blacklist: +15; `pause`: +5 |
| 7 | Calldata decode | `approve` / `setApprovalForAll` / `increaseAllowance` / `transfer(_from)` | Unlimited approval to an unknown spender: +50, critical |
| 8 | Drainer patterns | blacklist / hidden-fee / owner-mintable combos from checks 4+6 | warn (no extra score; already counted) |
| 9 | ERC-20 info | `eth_call` `name`/`symbol`/`decimals`/`totalSupply` | info only |

**Scoring:** `DANGER` if score ≥ 70 or any critical fail; `CAUTION` if
30–69 (or unverified source with score < 30); `SAFE` if < 30 and source
verified. Admin-gated functions (`mint`/`withdraw`/fee/`pause`) are
discounted to one third when there is **no live owner** who could call
them — WBNB's standard `withdraw(uint256)` (unwrap) must not turn a safe
token dangerous. Critical findings (`SELFDESTRUCT`/`DELEGATECALL` opcodes,
unlimited approval to an unknown spender, **confirmed-scam registry hit**)
are never discounted.

**Registry rule:** an entry is added only with public, verifiable
evidence of a confirmed incident (incident reports, victim counts,
on-chain traces) — never on suspicion. The registry is how Sentinel
catches what bytecode cannot: a drain that ran through a project's
website/connect flow leaves no malicious function in the contract, so no
on-chain signal alone justifies DANGER — but a confirmed incident does.
Absence from the registry is not proof of safety.

## Endpoints

Base URL after deploy: `https://sentinel.<account>.workers.dev`

| Endpoint | Description |
|----------|-------------|
| `GET /` | Demo page: paste an address, see the verdict — no curl needed. Includes preset buttons (WBNB, Mars Nexus, unlimited-approve calldata). |
| `GET /health` | `{"ok":true,"agent":"sentinel","version":"1.1.0","chains":["bsc","eth"]}` — for preflight + monitoring |
| `GET /check?chain=bsc&address=0x…` | Same as POST /check, try it from the browser address bar |
| `POST /check` | Main API. Body: `{"chain":"bsc","address":"0x…","calldata":"0x…","from":"0x…"}` (`calldata`/`from` optional) |
| `POST /agent` | Agent Games platform envelope: `{"type":"…","task_id":"…","mode":"…","input":{…}}` (+ optional `x-agent-games-signature` header). Accepts **any** envelope shape — never 404s or crashes. If the input contains a contract address it runs the same check and returns the verdict as `decision`; otherwise it returns an agent identity response. `GET /agent` also answers with the identity (some preflight probes use GET). |

### Try it

```bash
# health
curl https://sentinel.<account>.workers.dev/health

# check WBNB on BSC (GET variant)
curl "https://sentinel.<account>.workers.dev/check?chain=bsc&address=0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c"

# check a contract + the calldata you are about to sign (POST)
curl -X POST https://sentinel.<account>.workers.dev/check \
  -H 'Content-Type: application/json' \
  -d '{"chain":"bsc","address":"0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c",
       "calldata":"0x095ea7b3000000000000000000000000dead0000000000000000000000000000000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}'

# Agent Games envelope
curl -X POST https://sentinel.<account>.workers.dev/agent \
  -H 'Content-Type: application/json' \
  -d '{"type":"preflight","task_id":"test-1","mode":"check",
       "input":{"address":"0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c","chain":"bsc"}}'
```

## Example outputs (real, tested 2026-11-15 — see TESTS.md)

### WBNB on BSC — SAFE, score 5

```json
{
  "verdict": "SAFE", "risk_score": 5,
  "summary": "SAFE: no major risk signals found — verified source, no dangerous functions, no active owner risk. Standard caution still applies.",
  "checks": [
    {"name": "contract-exists", "status": "pass", "detail": "Contract bytecode present (… bytes).", "evidence": "eth_getCode via public RPC @ block 133651505 (BNB Smart Chain, chainId 56)"},
    {"name": "source-verified", "status": "pass", "detail": "Source code verified on Sourcify (match match) …", "evidence": "Sourcify v2 /contract/56/0xbb4C… @ block 133651505"},
    {"name": "owner", "status": "pass", "detail": "No owner() function responded …", "evidence": "eth_call owner() …"},
    {"name": "proxy", "status": "pass", "detail": "EIP-1967 implementation slot is empty …", "evidence": "eth_getStorageAt EIP-1967 slot …"},
    {"name": "selectors", "status": "pass", "detail": "Non-standard functions found (12 selectors total): withdraw(uint256), deposit(), uWjK9(uint256).", "evidence": "PUSH4 scan … + 4byte.directory @ block 133651505"},
    {"name": "token-info", "status": "pass", "detail": "ERC-20 token — Wrapped BNB (WBNB), decimals 18, totalSupply 1,567,955.9731 whole tokens …", "evidence": "eth_call name/symbol/decimals/totalSupply …"}
  ],
  "recommendation": "Looks fine on these checks. Still verify the dApp URL you connected through and never sign blind approvals.",
  "chain": "bsc", "address": "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c", "block_number": 133651505
}
```

(The 5 points are WBNB's standard `withdraw(uint256)` unwrap function,
discounted because there is no live owner. `uWjK9` is a junk candidate
name returned by 4byte.directory for one selector — it affects nothing;
only names matching risk patterns affect the score.)

### Mars Nexus `0xC4059D2F9F6F86695896e68F3E73E1e6cC3791c8` on BSC — DANGER, score 100

```json
{
  "verdict": "DANGER", "risk_score": 100,
  "summary": "DANGER: this contract shows critical risk signals (confirmed scam: Mars Nexus; unverified source; active owner 0xbde9…9bc7). Do not sign approvals or send funds to it.",
  "checks": [
    {"name": "reputation", "status": "fail", "detail": "LISTED in Sentinel's confirmed-scam registry: Mars Nexus (incident 2026-11-04). Confirmed drain: 33 agent wallets drained after connecting to the Mars Nexus site (QR connect flow)."},
    {"name": "source-verified", "status": "warn", "detail": "Source code NOT verified on Sourcify …"},
    {"name": "owner", "status": "warn", "detail": "Active owner: 0xbde905a3424f41d3a400a84e10a118e7df0f9bc7. Owner-only functions (if any) can still be called by this address."},
    {"name": "proxy", "status": "pass", "detail": "EIP-1967 implementation slot is empty …"},
    {"name": "selectors", "status": "pass", "detail": "Non-standard functions found (128 selectors total): gameController()."},
    {"name": "drainer-patterns", "status": "pass", "detail": "No blacklist / hidden-fee / unlimited-mint drainer pattern found …"},
    {"name": "token-info", "status": "pass", "detail": "Not an ERC-20 token …"}
  ],
  "recommendation": "Do NOT interact: do not approve, do not send funds, revoke any existing approval to this contract immediately."
}
```

**How this case works:** the contract itself shows no critical on-chain
function (no `mint`/`withdraw`/blacklist resolved, not a proxy) — the
November 2026 drain ran through the **website/connect flow**, which no
bytecode check can see. On on-chain evidence alone the contract scores
40 (unverified source +25, active owner +15), which was the v1.0.0
verdict: CAUTION. v1.1.0 adds the confirmed-scam registry: Mars Nexus
is a confirmed incident (33 wallets drained, 2026-11-04), so the
registry hit is a critical failure and the verdict is DANGER at the
capped score of 100. The on-chain checks still run, so the verdict
carries both the incident evidence and the contract's own signals. A
registry entry is never added on suspicion alone — see *Registry rule*
above. See *Limitations* for what this still cannot catch.

### Unlimited `approve` calldata (WBNB + spender `0xdead…0000`, amount 2²⁵⁶−1) — DANGER, score 55

```json
{
  "verdict": "DANGER", "risk_score": 55,
  "summary": "DANGER: this contract shows critical risk signals (risky function withdraw(uint256); unlimited approval to unknown spender). Do not sign approvals or send funds to it.",
  "checks": [
    {"name": "calldata", "status": "fail", "detail": "approve grants UNLIMITED approval to unknown spender 0xdead00000000000000000000000000000000. If signed, that spender could drain the full token balance."}
  ],
  "recommendation": "Do NOT interact: do not approve, do not send funds, revoke any existing approval to this contract immediately."
}
```

### WETH on Ethereum — SAFE, score 5

Same shape as WBNB: verified source, no owner, no proxy, standard
`deposit()`/`withdraw(uint256)` only. (Ethereum RPCs were flaky from the
build VM — see TESTS.md — but the check completed: block 26417252.)

## How it works (build context)

- **Runtime:** Cloudflare Workers, plain JavaScript, zero dependencies.
  One file: `src/index.js` (+ inline demo page). `wrangler.toml`,
  `package.json` (wrangler 4 as devDependency), MIT license.
- **RPC:** BSC first (public endpoints, raced in parallel — first valid
  result wins, so one rate-limited endpoint never blocks a check):
  `bsc-rpc.publicnode.com`, `bsc-dataseed.binance.org`,
  `bsc-dataseed1.defibit.io`, `bsc-dataseed1.ninicoin.io`. Ethereum:
  `eth-rpc.publicnode.com`, `cloudflare-eth.com`,
  `ethereum-rpc.publicnode.com`. 5 s timeout per RPC call.
- **Verification:** Sourcify **v2** (`GET /v2/contract/{chainId}/{address}`).
  Note: Sourcify API v1 was removed — the old `/check-by-addresses`
  endpoint now returns 404 telling callers to use v2.
- **Function names:** 4byte.directory (`/api/v1/signatures/?hex_signature=`),
  capped at 12 lookups per check, run in parallel. A selector can have
  many candidate names; Sentinel prefers a known canonical name, else
  the candidate with the fewest digits in its name (4byte is full of
  junk like `test266151307`), then the oldest entry.
- **Opcode scan:** single linear pass over runtime bytecode, skipping
  PUSH operands, so `DELEGATECALL`/`SELFDESTRUCT` bytes inside pushed
  data don't false-positive. The Solidity metadata trailer is stripped
  first — without that, plain WETH false-positived to DANGER during
  testing (fixed; see TESTS.md).
- **Failure mode:** every external call has a timeout and degrades its
  single check to `unknown` — one dead API never fails the whole verdict.
  Bad input returns 400 JSON; the worker never crashes on a malformed
  envelope.
- **No secrets, no state, no sign-in:** the worker holds no keys and
  stores nothing. The `x-agent-games-signature` header is accepted but
  there is no shared secret to verify against in this deployment (the
  endpoint is public and read-only by design — it cannot move funds).

## Limitations — what Sentinel can NOT detect

- **Off-chain / website-side attacks — unless already confirmed.** The
  Mars Nexus case is the proof: the drain ran through the site users
  connected to, not through a visibly malicious contract function.
  Sentinel checks the contract, not the dApp front-end, the URL you
  clicked, or the wallet prompt. The confirmed-scam registry covers
  incidents that are already known and evidenced — a *new* website-side
  attack with no confirmed incident yet will not be flagged as DANGER
  by the registry, only by whatever on-chain signals the contract
  itself shows.
- **Verified-but-malicious code.** A verified contract can still contain
  a backdoor written in plain sight; Sentinel flags risky *function
  names*, it does not audit logic. A `mint` that only the owner can call
  after a timelock looks the same as one without.
- **Unresolved selectors.** 4byte.directory doesn't know every function.
  An unknown selector is reported as unknown, not as safe — but it also
  can't be scored as dangerous.
- **Hidden admin roles.** `owner()` covers the Ownable pattern only.
  Contracts using `AccessControl` roles, multisigs, or a separate admin
  contract may have a live admin Sentinel can't see (owner check then
  says "no owner" — which is why admin-function weights are discounted,
  not zeroed, in that case).
- **Behaviour over time.** A proxy implementation can be upgraded after
  the check; a token's fees can change. A verdict is a snapshot at a
  block number, not a guarantee.
- **Not financial advice.** A SAFE verdict means "no major risk signals
  found by these checks", not "this is safe".

## Deploy (user steps)

Sentinel is deployed by the user from this repo — the build agent never
deploys (no Cloudflare account / token here).

```bash
git clone https://github.com/meigidimas/sentinel-guard   # repo name TBD at publish
cd sentinel-guard
npm install
npx wrangler login        # one-time, in your own browser
npx wrangler deploy       # -> https://sentinel.<your-account>.workers.dev
curl https://sentinel.<your-account>.workers.dev/health
```

Or connect the repo in the Cloudflare dashboard (Workers → Create →
import the GitHub repo) for automatic deploys on push. No environment
variables, secrets, KV, R2, or bindings are needed.

## Local test

```bash
npm install
npm test   # node test/run-local.mjs — calls the same handler wrangler
           # deploys, against live BSC/ETH RPCs. No wrangler needed.
```

## CPU budget (Workers free tier: ~10 ms CPU / request)

The worker is I/O-bound by design: a handful of parallel RPC/API calls
plus one linear bytecode pass (≤ ~24 KiB, PUSH-aware) and ≤ 12 small
4byte lookups. No heavy loops, no big JSON parsing. Wall-clock per
`/check` in testing was **1.4–9.6 s** (dominated by public-RPC and
4byte latency, which does not count toward CPU), comfortably inside the
platform's 60 s task limit. If a public RPC slows down, the 5 s per-call
timeout plus parallel racing bounds the worst case. See TESTS.md for the
measured numbers and the one environment caveat (wrangler dev outbound
fetch from the build VM).

## License

MIT — see [LICENSE](LICENSE).
