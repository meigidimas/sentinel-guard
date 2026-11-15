/**
 * Sentinel — wallet & transaction guard agent.
 *
 * Agent Games Wildcard entry. Cloudflare Workers, plain JavaScript, no
 * dependencies. Given an EVM contract address (and optionally the calldata
 * a user is about to sign), it checks the contract on-chain and returns a
 * reproducible SAFE / CAUTION / DANGER verdict with evidence per check.
 *
 * Endpoints:
 *   GET  /                        demo page (try it without curl)
 *   GET  /health                  {"ok":true,"agent":"sentinel",...}
 *   GET  /check?chain=bsc&address=0x...
 *   POST /check                   {"chain","address","calldata?","from?"}
 *   POST /agent                   Agent Games platform envelope (any shape)
 *
 * Design notes (CPU budget: Workers free tier allows ~10 ms CPU per
 * request; I/O waiting on RPC/API calls does not count):
 *   - All work is I/O-bound: a handful of JSON-RPC calls + 2 public APIs.
 *   - Bytecode scanning is a single linear pass with PUSH-operand
 *     skipping; no regex over the whole bytecode, no heavy loops.
 *   - 4byte.directory lookups are capped (12 selectors max) and run in
 *     parallel, each with its own short timeout.
 *   - Every external call has a timeout and a fallback; a failed
 *     dependency degrades one check to "unknown", never the whole request.
 *   - A curated confirmed-scam registry (KNOWN_SCAMS) covers what
 *     bytecode cannot: drains that ran through a project's website or
 *     connect flow. A registry hit is a critical failure.
 *
 * Sources (verified 2026-11-15 from this VM):
 *   - Sourcify API v1 is REMOVED. v2 endpoint used here:
 *     GET https://sourcify.dev/server/v2/contract/{chainId}/{address}
 *     ("match": "match" | "partial" | null).
 *   - 4byte.directory: GET /api/v1/signatures/?hex_signature=0x........
 *     Returns several candidate names per selector; we prefer a known
 *     canonical name, else the oldest entry (lowest id).
 *   - BSC public RPC bsc-rpc.publicnode.com rate-limits intermittently
 *     from some networks; fallback order below handles that.
 */

const VERSION = "1.1.0"; // plain const, NOT exported: Workers treats any
// top-level export as a named binding and rejects non-handler exports.

const CHAINS = {
  bsc: {
    chainId: 56,
    name: "BNB Smart Chain",
    rpcs: [
      "https://bsc-rpc.publicnode.com",
      "https://bsc-dataseed.binance.org",
      "https://bsc-dataseed1.defibit.io",
      "https://bsc-dataseed1.ninicoin.io",
    ],
  },
  eth: {
    chainId: 1,
    name: "Ethereum",
    rpcs: [
      "https://eth-rpc.publicnode.com",
      "https://cloudflare-eth.com",
      "https://ethereum-rpc.publicnode.com",
    ],
  },
};

const RPC_TIMEOUT_MS = 5000;
const API_TIMEOUT_MS = 4000;
const EIP1967_IMPL_SLOT =
  "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";
const MAX_UINT256 = (2n ** 256n) - 1n;

// Well-known 4-byte selectors (only ones verified against the standard
// ABIs / 4byte.directory; anything else is resolved via the 4byte API).
const KNOWN_SELECTORS = {
  "0x095ea7b3": "approve(address,uint256)",
  "0xa9059cbb": "transfer(address,uint256)",
  "0x23b872dd": "transferFrom(address,address,uint256)",
  "0xa22cb465": "setApprovalForAll(address,bool)",
  "0x70a08231": "balanceOf(address)",
  "0x18160ddd": "totalSupply()",
  "0x06fdde03": "name()",
  "0x95d89b41": "symbol()",
  "0x313ce567": "decimals()",
  "0x8da5cb5b": "owner()",
  "0x40c10f19": "mint(address,uint256)",
  "0xf2fde38b": "transferOwnership(address)",
  "0x715018a6": "renounceOwnership()",
  "0x8456cb59": "pause()",
  "0x3f4ba83a": "unpause()",
  "0x3ccfd60b": "withdraw()",
  "0x39509351": "increaseAllowance(address,uint256)",
  "0xa457c2d7": "decreaseAllowance(address,uint256)",
};

// Function-name patterns that raise risk. Checked against the resolved
// name (lowercased, before the "(").
const NAME_RISK = [
  { re: /selfdestruct|suicide|destroy\(/, weight: 40, level: "critical", label: "selfdestruct/destroy" },
  { re: /delegatecall/, weight: 40, level: "critical", label: "delegatecall" },
  { re: /withdraw|sweep|rescue|emergencywithdraw|drain/, weight: 15, level: "high", label: "withdraw/sweep" },
  { re: /setfee|settax|setblacklist|blacklist|addblacklist|setmax|setmaxtx|exclud/, weight: 15, level: "high", label: "fee/blacklist control" },
  { re: /^mint/, weight: 10, level: "high", label: "mint" },
  { re: /^pause/, weight: 5, level: "low", label: "pause" },
];
// Curated registry of contracts tied to CONFIRMED drain/scam incidents.
// Entries are added only with public, verifiable evidence (incident
// reports, victim counts, on-chain traces) — never on suspicion alone.
// This is how a guard catches what bytecode cannot: the Mars Nexus drain
// ran through the project's website/connect flow, not through a visibly
// malicious contract function, so no on-chain signal justifies DANGER on
// its own. A registry hit is a critical failure by design.
// Keys are lowercase addresses; `chain` scopes the entry to one chain.
const KNOWN_SCAMS = {
  "0xc4059d2f9f6f86695896e68f3e73e1e6cc3791c8": {
    chain: "bsc",
    name: "Mars Nexus",
    incident: "2026-11-04",
    evidence: "Confirmed drain: 33 agent wallets drained after connecting to the Mars Nexus site (QR connect flow). The contract is kept as the registry anchor for the project.",
  },
};

// Standard token functions: expected, not suspicious on their own.
const STANDARD_NAMES = new Set([
  "approve", "transfer", "transferfrom", "balanceof", "totalsupply",
  "allowance", "name", "symbol", "decimals", "owner",
  "transferownership", "renounceownership", "burn", "burnfrom",
  "setapprovalforall", "isapprovedforall", "supportsinterface",
  "tokenuri", "tokenbyindex", "tokenofownerbyindex",
]);

const ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;
const HEX_RE = /^0x[0-9a-fA-F]*$/;

/* ------------------------------------------------------------------ */
/* small helpers                                                       */
/* ------------------------------------------------------------------ */

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "access-control-allow-origin": "*",
      "cache-control": "no-store",
    },
  });
}

function shortHost(url) {
  try { return new URL(url).host; } catch { return url; }
}

function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

async function fetchWithTimeout(url, opts, ms) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), ms);
  try {
    return await fetch(url, { ...opts, signal: ctrl.signal });
  } finally {
    clearTimeout(t);
  }
}

/** Try all RPCs in parallel; first valid JSON-RPC result wins.
 *  Racing (instead of sequential fallback) because the listed public
 *  endpoints rate-limit intermittently from some networks — e.g.
 *  bsc-rpc.publicnode.com returned -32005 rate-limit errors from this VM
 *  on 2026-11-15 while bsc-dataseed.binance.org answered fine. A slow or
 *  rate-limited endpoint therefore never blocks the whole check. */
async function rpcCall(chain, method, params) {
  const cfg = CHAINS[chain];
  const attempts = cfg.rpcs.map(async (rpc) => {
    const res = await fetchWithTimeout(rpc, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
    }, RPC_TIMEOUT_MS);
    if (!res.ok) throw new Error(`HTTP ${res.status} from ${shortHost(rpc)}`);
    const data = await res.json();
    if (data.error) throw new Error(`${shortHost(rpc)}: ${data.error.message || data.error.code}`);
    if (data.result === undefined || data.result === null) throw new Error(`${shortHost(rpc)}: empty result`);
    return { result: data.result, rpc };
  });
  const errors = [];
  try {
    return await Promise.any(attempts.map((p) => p.catch((e) => { errors.push(e); throw e; })));
  } catch {
    throw new Error(errors.map((e) => e.message).join("; ") || "no RPC endpoint responded");
  }
}

function decodeAddressWord(wordHex) {
  // wordHex: "0x" + 64 hex chars; address is the last 40.
  if (!wordHex || wordHex.length < 42) return null;
  return "0x" + wordHex.slice(-40);
}

function decodeUint256(wordHex) {
  try { return BigInt(wordHex); } catch { return null; }
}

function shortAddr(a) {
  return a ? a.slice(0, 6) + "…" + a.slice(-4) : "?";
}

/* ------------------------------------------------------------------ */
/* bytecode analysis (single linear pass, PUSH-aware)                  */
/* ------------------------------------------------------------------ */

/**
 * Walk raw bytecode bytes, skipping PUSH operands, and report:
 *  - opcodes seen outside PUSH data (DELEGATECALL 0xf4, SELFDESTRUCT 0xff)
 *  - function selectors from the dispatcher pattern 0x63 <sel> 0x14...
 *    (PUSH4 selector followed by EQ) and from any PUSH4, as fallback.
 * Cheap: one pass over at most ~24 KiB of code.
 */
function analyzeBytecode(codeHex) {
  let hex = codeHex.startsWith("0x") ? codeHex.slice(2) : codeHex;
  // Strip the Solidity metadata trailer (CBOR hash at the end of the
  // bytecode). It is data, not code: scanning it as opcodes produces
  // false DELEGATECALL/SELFDESTRUCT hits (e.g. plain WETH flagged).
  for (const magic of ["a165627a7a72305820", "a264697066735822"]) {
    const idx = hex.lastIndexOf(magic);
    if (idx > 0) { hex = hex.slice(0, idx); break; }
  }
  const bytes = hex.length / 2;
  const selectors = new Map(); // selector -> "dispatch" | "push4"
  let hasDelegatecall = false;
  let hasSelfdestruct = false;
  let i = 0; // byte index
  const byteAt = (n) => parseInt(hex.slice(n * 2, n * 2 + 2), 16);
  while (i < bytes) {
    const op = byteAt(i);
    if (op === 0xf4) hasDelegatecall = true;
    if (op === 0xff) hasSelfdestruct = true;
    if (op >= 0x60 && op <= 0x7f) {
      // PUSH1..PUSH32: next (op - 0x5f) bytes are data, not opcodes.
      const pushLen = op - 0x5f;
      if (op === 0x63 && i + 5 <= bytes) {
        // PUSH4 <selector> — record it; dispatcher selectors are
        // followed by EQ (0x14) a few bytes later.
        const sel = "0x" + hex.slice((i + 1) * 2, (i + 5) * 2);
        const after = i + 5 < bytes ? byteAt(i + 5) : -1;
        const kind = after === 0x14 ? "dispatch" : "push4";
        if (!selectors.has(sel) || kind === "dispatch") selectors.set(sel, kind);
      }
      i += 1 + pushLen;
    } else {
      i += 1;
    }
  }
  const dispatch = [...selectors.entries()].filter(([, k]) => k === "dispatch").map(([s]) => s);
  const others = [...selectors.entries()].filter(([, k]) => k !== "dispatch").map(([s]) => s);
  return { selectors: [...dispatch, ...others], hasDelegatecall, hasSelfdestruct, sizeBytes: bytes };
}

/** Resolve selector names via 4byte.directory (capped, parallel). */
async function resolveSelectors(selectors) {
  const out = new Map(); // selector -> name | null
  for (const s of selectors) if (KNOWN_SELECTORS[s]) out.set(s, KNOWN_SELECTORS[s]);
  const unknown = selectors.filter((s) => !out.has(s)).slice(0, 12);
  await Promise.all(unknown.map(async (sel) => {
    try {
      const res = await fetchWithTimeout(
        `https://www.4byte.directory/api/v1/signatures/?hex_signature=${sel}`,
        { headers: { "user-agent": "sentinel/1.0.0 (agent-games-wildcard)" } },
        API_TIMEOUT_MS,
      );
      if (!res.ok) { out.set(sel, null); return; }
      const data = await res.json();
      const results = Array.isArray(data.results) ? data.results : [];
      if (!results.length) { out.set(sel, null); return; }
      // Prefer a canonical known name; else the most plausible real
      // function name: no long digit runs (4byte is full of junk like
      // "test266151307"), then the oldest entry (lowest id).
      const known = results.find((r) => {
        const n = (r.text_signature || "").split("(")[0].toLowerCase();
        return STANDARD_NAMES.has(n) || NAME_RISK.some((p) => p.re.test(n));
      });
      const digitCount = (s) => (s.match(/\d/g) || []).length;
      const plausible = [...results].sort((a, b) => {
        const da = digitCount(a.text_signature || ""), db = digitCount(b.text_signature || "");
        return da - db || a.id - b.id;
      })[0];
      const pick = known || plausible;
      out.set(sel, pick.text_signature || null);
    } catch {
      out.set(sel, null);
    }
  }));
  return out;
}

/* ------------------------------------------------------------------ */
/* calldata decoding                                                   */
/* ------------------------------------------------------------------ */

function decodeCalldata(calldata) {
  if (!calldata || typeof calldata !== "string" || !calldata.startsWith("0x")) return null;
  const hex = calldata.slice(2);
  if (hex.length < 8) return null;
  const selector = "0x" + hex.slice(0, 8).toLowerCase();
  const name = KNOWN_SELECTORS[selector] || null;
  const words = [];
  for (let i = 8; i + 64 <= hex.length; i += 64) words.push("0x" + hex.slice(i, i + 64));
  const info = { selector, name, raw: calldata };
  if (selector === "0x095ea7b3" && words.length >= 2) { // approve
    info.kind = "approve";
    info.spender = decodeAddressWord(words[0]);
    info.amount = decodeUint256(words[1]);
    info.unlimited = info.amount === MAX_UINT256;
  } else if (selector === "0xa22cb465" && words.length >= 2) { // setApprovalForAll
    info.kind = "setApprovalForAll";
    info.spender = decodeAddressWord(words[0]);
    info.approved = BigInt(words[1]) !== 0n;
    info.unlimited = info.approved === true;
    info.amount = info.approved ? MAX_UINT256 : 0n;
  } else if (selector === "0x39509351" && words.length >= 2) { // increaseAllowance
    info.kind = "increaseAllowance";
    info.spender = decodeAddressWord(words[0]);
    info.amount = decodeUint256(words[1]);
    info.unlimited = info.amount === MAX_UINT256;
  } else if (selector === "0xa9059cbb" && words.length >= 2) { // transfer
    info.kind = "transfer";
    info.to = decodeAddressWord(words[0]);
    info.amount = decodeUint256(words[1]);
  } else if (selector === "0x23b872dd" && words.length >= 3) { // transferFrom
    info.kind = "transferFrom";
    info.from = decodeAddressWord(words[0]);
    info.to = decodeAddressWord(words[1]);
    info.amount = decodeUint256(words[2]);
  } else {
    info.kind = "other";
  }
  return info;
}

/* ------------------------------------------------------------------ */
/* the check itself                                                    */
/* ------------------------------------------------------------------ */

export async function checkContract({ chain = "bsc", address, calldata = null, from = null }) {
  const cfg = CHAINS[chain];
  const checks = [];
  let score = 0;
  let criticalFail = false;
  const notes = [];
  // Hoisted so finish() is safe even from the earliest failure path.
  let verified = false;
  let verifyMatch = null;
  let isContract = false;

  const push = (name, status, detail, evidence) => checks.push({ name, status, detail, evidence });

  // 0. Current block (used as evidence anchor for every check).
  // Runs in parallel with the bytecode read (phase A).
  let blockNumber = null;
  let blockHex = null;
  let code = null;
  let codeRpc = null;
  let codeError = null;
  let blockTag = "block unknown";
  const ev = (method, rpc) => `${method} via ${rpc ? shortHost(rpc) : "public RPC"} @ ${blockTag} (${cfg.name}, chainId ${cfg.chainId})`;
  try {
    const [b, c] = await Promise.all([
      rpcCall(chain, "eth_blockNumber", []),
      rpcCall(chain, "eth_getCode", [address, "latest"]),
    ]);
    blockHex = b.result;
    blockNumber = parseInt(b.result, 16);
    blockTag = `block ${blockNumber}`;
    code = c.result; codeRpc = c.rpc;
  } catch (e) {
    // If the block-number call failed but getCode worked, retry getCode
    // alone so one flaky call does not kill the whole check.
    if (!code) {
      try {
        const c = await rpcCall(chain, "eth_getCode", [address, "latest"]);
        code = c.result; codeRpc = c.rpc;
      } catch (e2) { codeError = e2; }
    }
    if (!code) {
      push("contract-exists", "unknown", `Could not read bytecode: ${(codeError || e).message}`, `eth_getCode @ ${blockTag}`);
      return finish();
    }
  }
  // 1. Contract vs EOA.
  isContract = code && code !== "0x" && code.length > 2;
  if (!isContract) {
    push("contract-exists", "pass",
      "Address holds no bytecode — it is an externally owned account (EOA), not a contract. There is nothing to audit here.",
      ev("eth_getCode", codeRpc));
    return finish({ eoa: true });
  }
  push("contract-exists", "pass",
    `Contract bytecode present (${Math.floor((code.length - 2) / 2)} bytes).`,
    ev("eth_getCode", codeRpc));

  // 1b. Reputation: curated confirmed-scam registry. A hit is a critical
  // failure — a confirmed drain outweighs any on-chain reading. The
  // on-chain checks below still run, so the verdict also carries the
  // contract's own evidence.
  const scam = KNOWN_SCAMS[address.toLowerCase()];
  if (scam && scam.chain === chain) {
    score += 70;
    criticalFail = true;
    push("reputation", "fail",
      `LISTED in Sentinel's confirmed-scam registry: ${scam.name} (incident ${scam.incident}). ${scam.evidence}`,
      `curated registry (entry dated ${scam.incident}); on-chain checks below still run @ ${blockTag}`);
    notes.push(`confirmed scam: ${scam.name}`);
  } else {
    push("reputation", "pass",
      "Not listed in Sentinel's curated confirmed-scam registry — absence from the registry is not proof of safety; it only means no confirmed incident is tied to this address.",
      "curated registry lookup, local only");
  }

  // 2. Source verification (Sourcify v2 — v1 was removed).
  try {
    const res = await fetchWithTimeout(
      `https://sourcify.dev/server/v2/contract/${cfg.chainId}/${address}`,
      { headers: { "user-agent": "sentinel/1.0.0 (agent-games-wildcard)" } },
      API_TIMEOUT_MS,
    );
    if (res.ok) {
      const data = await res.json();
      verifyMatch = data.match || null;
      verified = verifyMatch === "match" || verifyMatch === "partial";
    }
  } catch { /* unverified/unknown below */ }
  if (verified) {
    push("source-verified", "pass",
      `Source code verified on Sourcify (${verifyMatch} match) — the deployed bytecode matches published source, so the code can be read.`,
      `Sourcify v2 /contract/${cfg.chainId}/${address} @ ${blockTag}`);
  } else {
    score += 25;
    push("source-verified", "warn",
      "Source code NOT verified on Sourcify — the deployed bytecode cannot be matched to readable source, so hidden behaviour cannot be ruled out by reading code.",
      `Sourcify v2 /contract/${cfg.chainId}/${address} @ ${blockTag}`);
    notes.push("unverified source");
  }

  // 3+4. Owner probe + proxy slot, in parallel (independent calls).
  const [ownerRes, proxyRes] = await Promise.allSettled([
    rpcCall(chain, "eth_call", [{ to: address, data: "0x8da5cb5b" }, "latest"]),
    rpcCall(chain, "eth_getStorageAt", [address, EIP1967_IMPL_SLOT, "latest"]),
  ]);
  let owner = null;
  let ownerKnown = false;
  if (ownerRes.status === "fulfilled") {
    const r = ownerRes.value;
    if (r.result && r.result !== "0x" && r.result.length >= 42) {
      owner = decodeAddressWord(r.result);
      ownerKnown = true;
    }
  }
  const ownerActive = ownerKnown && owner !== ZERO_ADDRESS;
  if (!ownerKnown) {
    push("owner", "pass",
      "No owner() function responded — no single owner address controls this contract through the standard Ownable pattern.",
      ev("eth_call owner()", null));
  } else if (owner === ZERO_ADDRESS) {
    push("owner", "pass",
      "owner() returns the zero address — ownership is renounced; nobody can call owner-only functions.",
      ev("eth_call owner()", null));
  } else {
    score += 15;
    push("owner", "warn",
      `Active owner: ${owner}. Owner-only functions (if any) can still be called by this address.`,
      ev("eth_call owner()", null));
    notes.push(`active owner ${shortAddr(owner)}`);
  }

  // 4. Proxy (EIP-1967 implementation slot).
  let implementation = null;
  if (proxyRes.status === "fulfilled") {
    const r = proxyRes.value;
    if (r.result && r.result !== "0x" && BigInt(r.result) !== 0n) {
      implementation = decodeAddressWord(r.result);
    }
  }
  if (implementation) {
    score += 10;
    if (ownerKnown && owner !== ZERO_ADDRESS) score += 10;
    push("proxy", "warn",
      `EIP-1967 proxy — logic lives at implementation ${implementation}, which the owner can replace. The code you see today may not be the code that runs tomorrow.`,
      ev("eth_getStorageAt EIP-1967 slot", null));
    notes.push("EIP-1967 proxy");
  } else {
    push("proxy", "pass",
      "EIP-1967 implementation slot is empty — not a proxy; the deployed logic cannot be swapped out from under users.",
      ev("eth_getStorageAt EIP-1967 slot", null));
  }

  // 5. Selector analysis (+ opcode scan).
  const { selectors, hasDelegatecall, hasSelfdestruct } = analyzeBytecode(code);
  const names = await resolveSelectors(selectors);
  const found = [];
  let selectorStatus = "pass";
  let selectorScore = 0;
  let selectorDetail = "";
  for (const sel of selectors) {
    const full = names.get(sel);
    if (!full) continue;
    const fname = full.split("(")[0].toLowerCase();
    if (STANDARD_NAMES.has(fname)) continue;
    found.push(full);
    for (const rule of NAME_RISK) {
      if (rule.re.test(fname)) {
        // Admin-gated functions (mint/withdraw/fee/pause) are only fully
        // dangerous when a live owner can call them. With no owner (or a
        // renounced one) they are discounted — e.g. WBNB's standard
        // withdraw() for unwrapping must not turn a safe token DANGER.
        // Critical rules (selfdestruct/delegatecall) are never discounted.
        let w = rule.weight;
        if (rule.level !== "critical" && !ownerActive) w = Math.max(1, Math.ceil(w / 3));
        score += w;
        selectorScore += w;
        if (rule.level === "critical") { criticalFail = true; selectorStatus = "fail"; }
        notes.push(`risky function ${full}`);
        break;
      }
    }
  }
  if (selectorScore >= 10 && selectorStatus !== "fail") selectorStatus = "warn";
  if (hasDelegatecall) { score += 40; criticalFail = true; selectorStatus = "fail"; notes.push("DELEGATECALL opcode in bytecode"); }
  if (hasSelfdestruct) { score += 40; criticalFail = true; selectorStatus = "fail"; notes.push("SELFDESTRUCT opcode in bytecode"); }
  const riskyList = found.length ? found.slice(0, 20).join(", ") : "none";
  selectorDetail = found.length
    ? `Non-standard functions found (${selectors.length} selectors total): ${riskyList}${found.length > 20 ? ` (+${found.length - 20} more)` : ""}.`
    : `No non-standard risky functions among ${selectors.length} selectors; standard token functions only.`;
  if (hasDelegatecall) selectorDetail += " Bytecode contains a DELEGATECALL opcode (PUSH-aware scan).";
  if (hasSelfdestruct) selectorDetail += " Bytecode contains a SELFDESTRUCT opcode (PUSH-aware scan).";
  push("selectors", selectorStatus, selectorDetail,
    `PUSH4 scan of eth_getCode bytecode (${selectors.length} selectors) + 4byte.directory @ ${blockTag}`);

  // 6. Calldata approval decoding.
  let approval = null;
  if (calldata) {
    const dec = decodeCalldata(calldata);
    if (!dec) {
      push("calldata", "unknown", "Calldata could not be parsed (too short or not hex).", "local decode, no chain data");
    } else if (dec.kind === "approve" || dec.kind === "setApprovalForAll" || dec.kind === "increaseAllowance") {
      approval = dec;
      const spenderKnown = dec.spender && (dec.spender.toLowerCase() === address.toLowerCase()
        || (from && dec.spender.toLowerCase() === from.toLowerCase()));
      const amtText = dec.kind === "setApprovalForAll"
        ? (dec.approved ? "all tokens (setApprovalForAll=true)" : "revoked (false)")
        : dec.unlimited ? "UNLIMITED (2^256-1)" : String(dec.amount);
      if (dec.unlimited && !spenderKnown) {
        score += 50; criticalFail = true;
        push("calldata", "fail",
          `${dec.kind} grants UNLIMITED approval to unknown spender ${dec.spender}. If signed, that spender could drain the full token balance.`,
          `local decode of supplied calldata; spender ${dec.spender} is not the checked contract or the sender`);
        notes.push("unlimited approval to unknown spender");
      } else if (dec.unlimited) {
        score += 10;
        push("calldata", "warn",
          `${dec.kind} grants UNLIMITED approval (${amtText}) to ${dec.spender}, which is the checked contract itself or your own address — lower risk, but still unlimited. Prefer a limited amount.`,
          "local decode of supplied calldata");
      } else {
        push("calldata", "pass",
          `${dec.kind} to ${dec.spender}, amount ${amtText} — a limited approval.`,
          "local decode of supplied calldata");
      }
    } else if (dec.kind === "transfer" || dec.kind === "transferFrom") {
      push("calldata", "pass",
        `${dec.kind} decoded: ${dec.from ? `from ${dec.from} ` : ""}to ${dec.to}, amount ${dec.amount}. No approval is granted by this calldata.`,
        "local decode of supplied calldata");
    } else {
      push("calldata", "pass",
        `Calldata selector ${dec.selector}${dec.name ? ` (${dec.name})` : " (unknown function)"} — not an approval, so it grants no token allowance.`,
        "local decode of supplied calldata");
    }
  } else {
    push("calldata", "pass",
      "No calldata supplied — approval risk was not evaluated. Paste the calldata you are about to sign to check it.",
      "no chain data; local only");
  }

  // 7. Drainer patterns: blacklist/pause/fee + mint-with-owner.
  const riskyNames = found.map((f) => f.split("(")[0].toLowerCase());
  const drainerFlags = [];
  if (riskyNames.some((n) => /blacklist/.test(n))) drainerFlags.push("blacklist function can block sells/transfers");
  if (riskyNames.some((n) => /^mint/.test(n)) && ownerKnown && owner !== ZERO_ADDRESS) drainerFlags.push("owner can mint new tokens (supply not fixed)");
  if (riskyNames.some((n) => /setfee|settax/.test(n))) drainerFlags.push("owner can change fees (hidden-fee risk)");
  if (riskyNames.some((n) => /^pause/.test(n)) && ownerKnown && owner !== ZERO_ADDRESS) drainerFlags.push("owner can pause the contract");
  if (drainerFlags.length) {
    push("drainer-patterns", "warn",
      `Drainer-risk patterns: ${drainerFlags.join("; ")}.`,
      `selector names from check 5, owner from eth_call owner() @ ${blockTag}`);
    notes.push("drainer patterns");
  } else {
    push("drainer-patterns", "pass",
      "No blacklist / hidden-fee / unlimited-mint drainer pattern found in the resolved function names.",
      `selector names from check 5 @ ${blockTag}`);
  }

  // 8. ERC-20 token info (best effort; non-token contracts just skip).
  try {
    const calls = {
      name: "0x06fdde03", symbol: "0x95d89b41",
      decimals: "0x313ce567", totalSupply: "0x18160ddd",
    };
    const out = {};
    await Promise.all(Object.entries(calls).map(async ([k, data]) => {
      try {
        const r = await rpcCall(chain, "eth_call", [{ to: address, data }, "latest"]);
        out[k] = r.result;
      } catch { out[k] = null; }
    }));
    const isToken = out.decimals && out.decimals !== "0x" && out.totalSupply && out.totalSupply !== "0x";
    if (isToken) {
      const dec = Number(decodeUint256(out.decimals) ?? 18n);
      const supply = decodeUint256(out.totalSupply);
      const decodeStr = (h) => {
        if (!h || h === "0x" || h.length < 130) return null;
        try {
          // ABI-encoded string: 0x + offset word (chars 2..66) +
          // length word (chars 66..130) + UTF-8 bytes from char 130.
          const len = Number(BigInt("0x" + h.slice(66, 130)));
          if (len < 0 || len > 200) return null;
          const bytes = h.slice(130, 130 + len * 2);
          return decodeURIComponent(bytes.replace(/(..)/g, "%$1"));
        } catch { return null; }
      };
      const name = decodeStr(out.name);
      const symbol = decodeStr(out.symbol);
      let supplyText = "unknown";
      if (supply !== null) {
        const scale = 10n ** BigInt(dec);
        const whole = supply / scale;
        const frac = supply % scale;
        const fracStr = frac.toString().padStart(dec, "0").slice(0, 4).replace(/0+$/, "");
        supplyText = `${whole.toLocaleString("en-US")}${fracStr ? "." + fracStr : ""} whole tokens (${supply} raw units, ${dec} decimals)`;
      }
      push("token-info", "pass",
        `ERC-20 token${name ? ` — ${name}` : ""}${symbol ? ` (${symbol})` : ""}, decimals ${dec}, totalSupply ${supplyText}.`,
        ev("eth_call name/symbol/decimals/totalSupply", null));
    } else {
      push("token-info", "pass",
        "Not an ERC-20 token (name/symbol/decimals/totalSupply calls did not return token data) — nothing token-specific to report.",
        ev("eth_call name/symbol/decimals/totalSupply", null));
    }
  } catch {
    push("token-info", "unknown", "Token info calls failed.", ev("eth_call", null));
  }

  return finish();

  function finish(extra = {}) {
    if (score > 100) score = 100;
    let verdict;
    if (criticalFail || score >= 70) verdict = "DANGER";
    else if (score >= 30) verdict = "CAUTION";
    else if (!verified && isContract) verdict = "CAUTION"; // unverified alone is never SAFE
    else verdict = "SAFE";
    const summary = extra.eoa
      ? "This address is an externally owned account, not a contract — there is nothing to audit."
      : verdict === "DANGER"
        ? `DANGER: this contract shows critical risk signals (${notes.slice(0, 3).join("; ") || "high risk score"}). Do not sign approvals or send funds to it.`
        : verdict === "CAUTION"
          ? `CAUTION: this contract has risk signals (${notes.slice(0, 3).join("; ") || "unverified source"}). Do not approve unlimited spending; verify before signing.`
          : "SAFE: no major risk signals found — verified source, no dangerous functions, no active owner risk. Standard caution still applies.";
    const recommendation = verdict === "DANGER"
      ? "Do NOT interact: do not approve, do not send funds, revoke any existing approval to this contract immediately."
      : verdict === "CAUTION"
        ? "Proceed only if you understand the flagged items; never grant unlimited approval, use a limited amount, and prefer a fresh wallet for first interaction."
        : "Looks fine on these checks. Still verify the dApp URL you connected through and never sign blind approvals.";
    return {
      verdict, risk_score: score, summary, checks, recommendation,
      chain, address: address.toLowerCase(), block_number: blockNumber,
      checked_at: new Date().toISOString(),
    };
  }
}

/* ------------------------------------------------------------------ */
/* demo page                                                           */
/* ------------------------------------------------------------------ */

function demoPage() {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sentinel — wallet &amp; transaction guard</title>
<style>
body{font-family:system-ui,sans-serif;max-width:760px;margin:32px auto;padding:0 16px;color:#111}
h1{font-size:26px;margin-bottom:4px} p{color:#444} label{display:block;margin:12px 0 4px;font-weight:600}
input,select,textarea{width:100%;padding:10px;font-size:15px;border:1px solid #bbb;border-radius:8px;box-sizing:border-box}
button{margin-top:14px;padding:11px 18px;font-size:15px;border:0;border-radius:8px;background:#111;color:#fff;cursor:pointer}
button.preset{background:#eee;color:#111;margin-right:8px;margin-top:8px}
pre{background:#f5f5f5;padding:14px;border-radius:8px;overflow:auto;font-size:13px;white-space:pre-wrap}
.verdict{font-size:20px;font-weight:700;margin-top:18px}
.SAFE{color:#0a7a2f}.CAUTION{color:#9a6a00}.DANGER{color:#c00}
table{border-collapse:collapse;width:100%;margin-top:12px;font-size:14px}
td,th{border:1px solid #ddd;padding:8px;text-align:left;vertical-align:top}
</style></head><body>
<h1>🛡 Sentinel</h1>
<p>Wallet &amp; transaction guard. Paste a contract address and Sentinel checks it
on-chain — source verification, owner, proxy, dangerous functions, and (if you paste
it) the calldata you are about to sign — then gives a verdict with reproducible evidence.</p>
<form id="f">
<label>Chain</label>
<select id="chain"><option value="bsc">BNB Smart Chain (BSC)</option><option value="eth">Ethereum</option></select>
<label>Contract address</label>
<input id="address" placeholder="0x..." value="0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c">
<label>Calldata (optional — the hex you are about to sign)</label>
<textarea id="calldata" rows="2" placeholder="0x095ea7b3..."></textarea>
<label>Your wallet address (optional)</label>
<input id="from" placeholder="0x...">
<button type="submit">Check contract</button>
</form>
<div>
<button class="preset" data-a="0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c" data-c="">WBNB (safe example)</button>
<button class="preset" data-a="0xC4059D2F9F6F86695896e68F3E73E1e6cC3791c8" data-c="">Mars Nexus (real drain case)</button>
<button class="preset" data-a="0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c" data-c="0x095ea7b3000000000000000000000000dead000000000000000000000000000000000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff">Unlimited approve (calldata demo)</button>
</div>
<div id="out"></div>
<script>
var form=document.getElementById('f'), out=document.getElementById('out');
document.querySelectorAll('.preset').forEach(function(b){
  b.addEventListener('click',function(){
    document.getElementById('address').value=b.getAttribute('data-a');
    document.getElementById('calldata').value=b.getAttribute('data-c');
    form.dispatchEvent(new Event('submit'));
  });
});
form.addEventListener('submit',async function(e){
  e.preventDefault();
  out.innerHTML='<p>Checking on-chain…</p>';
  var body={chain:document.getElementById('chain').value,
    address:document.getElementById('address').value.trim(),
    calldata:document.getElementById('calldata').value.trim()||undefined,
    from:document.getElementById('from').value.trim()||undefined};
  try{
    var r=await fetch('/check',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)});
    var d=await r.json();
    if(!r.ok){out.innerHTML='<pre>'+JSON.stringify(d,null,2)+'</pre>';return;}
    var h='<div class="verdict '+d.verdict+'">'+d.verdict+' — risk '+d.risk_score+'/100</div><p>'+d.summary+'</p><p><b>Recommendation:</b> '+d.recommendation+'</p>';
    h+='<table><tr><th>Check</th><th>Status</th><th>Detail</th><th>Evidence</th></tr>';
    d.checks.forEach(function(c){h+='<tr><td>'+c.name+'</td><td>'+c.status+'</td><td>'+c.detail+'</td><td>'+c.evidence+'</td></tr>';});
    h+='</table><pre>'+JSON.stringify(d,null,2)+'</pre>';
    out.innerHTML=h;
  }catch(err){out.innerHTML='<p>Request failed: '+err.message+'</p>';}
});
</script>
</body></html>`;
}

/* ------------------------------------------------------------------ */
/* /agent envelope (Agent Games platform)                              */
/* ------------------------------------------------------------------ */

function findAddressIn(input) {
  if (!input || typeof input !== "object") return null;
  const keys = ["address", "contract", "contract_address", "target", "token", "contractAddress"];
  for (const k of keys) {
    if (typeof input[k] === "string" && ADDRESS_RE.test(input[k].trim())) return input[k].trim();
  }
  // Fall back to scanning any string value for an address.
  const scan = (v) => {
    if (typeof v === "string") {
      const m = v.match(/0x[0-9a-fA-F]{40}/);
      return m ? m[0] : null;
    }
    if (v && typeof v === "object") {
      for (const x of Object.values(v)) { const r = scan(x); if (r) return r; }
    }
    return null;
  };
  return scan(input);
}

async function handleAgent(request) {
  let body = {};
  try { body = await request.json(); } catch { body = {}; }
  const input = (body && typeof body === "object" && body.input && typeof body.input === "object") ? body.input : body;
  const address = findAddressIn(input);
  const chain = (input && typeof input.chain === "string" && CHAINS[input.chain.toLowerCase()])
    ? input.chain.toLowerCase() : "bsc";
  const base = {
    agent: "sentinel", version: VERSION,
    task_id: body.task_id || body.taskId || null,
    type: body.type || "check",
  };
  if (!address) {
    // No contract in the envelope: identify the agent instead of erroring.
    return json({
      ...base, status: "ok",
      decision: { verdict: "UNKNOWN", risk_score: null, summary: "Sentinel is a wallet & transaction guard. Send {\"input\":{\"chain\":\"bsc\",\"address\":\"0x...\"}} to check a contract." },
      capabilities: ["check contract safety on BSC and Ethereum", "decode approve/setApprovalForAll calldata", "detect proxy, owner, unverified source, dangerous functions"],
      endpoints: { health: "/health", check: "/check", demo: "/" },
    });
  }
  const calldata = typeof input.calldata === "string" ? input.calldata
    : typeof input.data === "string" ? input.data : null;
  const from = typeof input.from === "string" ? input.from : null;
  try {
    const result = await checkContract({ chain, address, calldata, from });
    return json({
      ...base, status: "ok",
      decision: { verdict: result.verdict, risk_score: result.risk_score, summary: result.summary },
      result,
    });
  } catch (e) {
    return json({ ...base, status: "error", error: String(e && e.message || e),
      decision: { verdict: "UNKNOWN", risk_score: null, summary: "Check failed: upstream RPC/API unreachable." } }, 200);
  }
}

/* ------------------------------------------------------------------ */
/* router                                                              */
/* ------------------------------------------------------------------ */

export default {
  async fetch(request) {
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";
    try {
      if (request.method === "OPTIONS") {
        return new Response(null, { status: 204, headers: { "access-control-allow-origin": "*", "access-control-allow-methods": "GET,POST,OPTIONS", "access-control-allow-headers": "content-type,x-agent-games-signature" } });
      }
      if (path === "/" && request.method === "GET") {
        return new Response(demoPage(), { headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" } });
      }
      if (path === "/health") {
        return json({ ok: true, agent: "sentinel", version: VERSION, chains: Object.keys(CHAINS) });
      }
      if (path === "/check" && request.method === "GET") {
        const chain = (url.searchParams.get("chain") || "bsc").toLowerCase();
        const address = (url.searchParams.get("address") || "").trim();
        if (!CHAINS[chain]) return json({ error: `unknown chain '${chain}'`, chains: Object.keys(CHAINS) }, 400);
        if (!ADDRESS_RE.test(address)) return json({ error: "address must be a 0x-prefixed 40-hex-char EVM address" }, 400);
        const result = await checkContract({
          chain, address,
          calldata: url.searchParams.get("calldata") || null,
          from: url.searchParams.get("from") || null,
        });
        return json(result);
      }
      if (path === "/check" && request.method === "POST") {
        let body = {};
        try { body = await request.json(); } catch { return json({ error: "body must be valid JSON" }, 400); }
        const chain = String(body.chain || "bsc").toLowerCase();
        const address = String(body.address || "").trim();
        if (!CHAINS[chain]) return json({ error: `unknown chain '${chain}'`, chains: Object.keys(CHAINS) }, 400);
        if (!ADDRESS_RE.test(address)) return json({ error: "address must be a 0x-prefixed 40-hex-char EVM address" }, 400);
        if (body.calldata !== undefined && body.calldata !== null && (typeof body.calldata !== "string" || !HEX_RE.test(body.calldata))) {
          return json({ error: "calldata must be a 0x-prefixed hex string" }, 400);
        }
        const result = await checkContract({ chain, address, calldata: body.calldata || null, from: body.from || null });
        return json(result);
      }
      if (path === "/agent" && request.method === "POST") {
        return await handleAgent(request);
      }
      if (path === "/agent" && request.method === "GET") {
        // Preflight probes sometimes use GET; identify instead of 404.
        return json({ agent: "sentinel", version: VERSION, status: "ok",
          note: "POST a JSON envelope to /agent to check a contract.",
          endpoints: { health: "/health", check: "/check", demo: "/" } });
      }
      return json({ error: "not found", agent: "sentinel", endpoints: ["/", "/health", "/check", "/agent"] }, 404);
    } catch (e) {
      return json({ error: "internal error", detail: String(e && e.message || e), agent: "sentinel" }, 500);
    }
  },
};
