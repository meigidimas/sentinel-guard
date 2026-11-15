# Sentinel — test record

All tests run 2026-11-15 (WIB, UTC+7) from the build VM, against **live**
BSC/ETH public RPCs and public APIs (Sourcify v2, 4byte.directory).
Harness: `node test/run-local.mjs` — calls the exact same worker handler
(`src/index.js` default export) that wrangler deploys, via plain Node
`Request`/`Response`. Exit 0 = all smoke cases passed.

## Final run (after all fixes) — 2026-11-15 ~09:05 WIB

| # | Test | HTTP | Latency | Result |
|---|------|------|---------|--------|
| 1 | `GET /` demo page | 200 | 6 ms | HTML 4,050 chars, form + presets present |
| 2 | `GET /health` | 200 | 0 ms | `{"ok":true,"agent":"sentinel","version":"1.0.0","chains":["bsc","eth"]}` |
| 3 | `POST /check` WBNB (BSC) | 200 | 6.4 s | **SAFE, score 5** — verified, no owner, no proxy, token "Wrapped BNB (WBNB)", supply 1,567,955.97 |
| 4 | `POST /check` Mars Nexus `0xC4059D2F…3791c8` (BSC) | 200 | 8.2 s | **CAUTION, score 40** — unverified source (+25), active owner `0xbde905a3…f0f9bc7` (+15); 22,322 bytes; 128 selectors, only `gameController()` non-standard; not a proxy; not an ERC-20. Block 133651517 |
| 5 | `POST /check` WBNB + unlimited `approve` calldata (spender `0xdead…0000`, amount 2²⁵⁶−1) | 200 | 2.8 s | **DANGER, score 55** — `calldata: fail`, "approve grants UNLIMITED approval to unknown spender" |
| 6 | `POST /agent` preflight envelope (`test-1`, WBNB) | 200 | 1.5 s | `decision: {verdict SAFE, risk_score 5}`, `task_id` echoed |
| 7 | `POST /agent` empty envelope (`{type:"ping", input:{}}`) | 200 | 0 ms | Identity response, no crash |
| 8 | `GET /check?chain=bsc&address=<WBNB>` | 200 | 1.4 s | **SAFE, score 5** |
| 9 | `POST /check` bad address `0x1234` | 400 | 0 ms | `{"error":"address must be a 0x-prefixed 40-hex-char EVM address"}` |

Extra probe (same day): `POST /check` WETH on Ethereum
`0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2` → **SAFE, score 5**,
"Wrapped Ether (WETH)", supply 2,123,954.96, block 26417252.

Latency varies run to run (1.4–9.6 s across runs) — dominated by public
RPC + 4byte.directory response times, not by local compute. All well
inside the platform's 60 s task limit.

## Bugs found by testing — and fixed

1. **Harness calldata malformed (first run).** The unlimited-approve
   test calldata was 2 hex chars short (spurious `pass` instead of the
   expected `fail`). Fixed the spender word (24 zero-bytes + 40-char
   address = 64 chars; total calldata 138 chars) in both the harness
   and the demo-page preset. Lesson: hand-built calldata must be
   length-checked; the worker itself was correct.
2. **WBNB false `selectors: warn` (score 15).** WBNB's standard
   `withdraw(uint256)` unwrap function scored full admin weight. Fixed
   with the owner-gated discount: admin functions count one third when
   there is no live owner. WBNB is now SAFE score 5, selectors `pass`.
3. **`export const VERSION` broke wrangler dev.** Workers treats any
   top-level export as a named binding; a string export fails the
   runtime with "Incorrect type for map entry 'VERSION'". Changed to a
   plain `const`. (Caught only by running wrangler dev — the Node
   harness does not enforce this.)
4. **TDZ crash on early failure path.** `finish()` referenced `verified`
   before its `let` declaration when the bytecode read failed, masking
   the real error with "Cannot access 'verified' before initialization".
   Hoisted `verified` / `isContract` declarations to the top of
   `checkContract`.
5. **WETH false DANGER (score 45).** The opcode scan read the Solidity
   metadata trailer as code and "found" a `SELFDESTRUCT`/`DELEGATECALL`
   opcode. Fixed by stripping the metadata trailer (`a165…` /
   `a264…` magic) before scanning. WETH is now SAFE score 5.
6. **Token name/symbol decoded as null.** ABI string offsets were
   wrong (length word read from the data area). Fixed offsets
   (offset word chars 2–66, length word 66–130, data from 130).
   WBNB/WETH names now decode ("Wrapped BNB", "Wrapped Ether").
7. **4byte junk names.** `test266151307()` was picked for a WBNB
   selector. Fixed pick heuristic: known canonical name first, else
   fewest digits in the name, then oldest entry. One junk name remains
   (`uWjK9(uint256)`) — displayed only, affects no score.

## Environment findings (verified from the build VM)

- **Sourcify API v1 is removed.** `/check-by-addresses` returns 404
  ("API v1 is removed. Use API v2"). Sentinel uses v2
  (`/v2/contract/{chainId}/{address}`) — verified working for WBNB
  (`match`) and Mars Nexus (`match: null`).
- **BSC `bsc-rpc.publicnode.com` rate-limits** intermittently from this
  VM (`-32005` rate-limit error). `bsc-dataseed.binance.org`,
  `bsc-dataseed1.defibit.io`, `bsc-dataseed1.ninicoin.io` answered fine.
  Sentinel races all RPCs in parallel (first valid result wins) so one
  rate-limited endpoint never blocks a check.
- **Ethereum:** `eth-rpc.publicnode.com` unreachable from this VM
  (empty response); `cloudflare-eth.com` answered with errors for
  `eth_blockNumber` on one probe but the WETH check completed — the
  race fell through to a working endpoint.
- **BUSD example from the plan is NOT usable as-is:** Sourcify v2
  rejects the address as written (`0xe9e7CEA3DedcA5984780Bafc599bD3cF6AaA1D0c`
  — checksum mismatch). WBNB is the SAFE example instead.
- **wrangler dev cannot reach the internet from this VM (NOT a code
  bug).** The VM's egress goes through an authenticated HTTP proxy;
  Node's fetch honours the proxy env vars (verified: fetch works with
  proxy, fails without it), but the workerd runtime used by
  `wrangler dev` does not use proxy env vars, so all outbound fetch
  from the dev server fails (`internal error` from workerd). The worker
  code is validated by the Node harness against live RPCs instead.
  **After real deploy to Cloudflare Workers this does not apply**
  (Workers fetch goes direct) — but the deployed endpoint MUST be
  re-tested with a live `/check` after deploy; the Node harness cannot
  prove the deployed runtime.
- **wrangler 3.114.17 vs compatibility_date 2026-11-15:** v3 only
  supports up to `2025-07-18` and silently falls back. Upgraded to
  wrangler **4.162.0** (npm install succeeded, 25 s); the
  `2026-11-15` date is now accepted.
- **wrangler dev does start and serve locally:** `/health` returned
  200 from `http://127.0.0.1:8787` — only outbound fetch was blocked.

## Not yet tested (needs the deployed endpoint)

- A live `/check` against the real `*.workers.dev` URL (see above).
- The Agent Games preflight probe against the deployed URL (format
  unknown until the dashboard is used; `/agent` is built to accept any
  envelope shape).
- CPU time per request inside the real Workers runtime (free tier:
  10 ms). Design is I/O-bound with one linear bytecode pass and ≤ 12
  small 4byte lookups; expected to fit, but only the deployed runtime
  can measure it.
