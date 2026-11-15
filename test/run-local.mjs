// Local test harness: calls the SAME worker handler (src/index.js) that
// wrangler deploys, via plain Node Request/Response — no wrangler needed.
// Usage: node test/run-local.mjs [base-url-unused]  — prints one JSON line
// per case plus a human summary. Exit 0 only if the smoke cases pass.
import worker from "../src/index.js";

const WBNB = "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c";
const MARS = "0xC4059D2F9F6F86695896e68F3E73E1e6cC3791c8";
const SPENDER = "0xdead00000000000000000000000000000000";
const UNLIMITED_APPROVE =
  "0x095ea7b3" +
  "000000000000000000000000dead000000000000000000000000000000000000" +
  "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

async function call(method, path, body) {
  const t0 = Date.now();
  const req = new Request(`http://localhost${path}`, {
    method,
    headers: { "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const res = await worker.fetch(req);
  const text = await res.text();
  let data;
  try { data = JSON.parse(text); } catch { data = { _raw: text.slice(0, 300) }; }
  return { status: res.status, ms: Date.now() - t0, data, raw: text };
}

function verdictLine(d) {
  if (!d || typeof d !== "object") return String(d);
  const checks = Array.isArray(d.checks)
    ? d.checks.map((c) => `${c.name}:${c.status}`).join(", ")
    : "-";
  return `verdict=${d.verdict} score=${d.risk_score} | ${d.summary || ""}\n  checks: ${checks}\n  recommendation: ${d.recommendation || ""}`;
}

const results = [];
async function test(name, fn) {
  try {
    const r = await fn();
    results.push({ name, ...r });
    console.log(`\n=== ${name} ===\nstatus=${r.status} latency=${r.ms}ms\n${r.note || ""}`);
  } catch (e) {
    results.push({ name, status: "ERROR", ms: null, note: String(e && e.message || e) });
    console.log(`\n=== ${name} ===\nERROR: ${e && e.message || e}`);
  }
}

await test("GET / (demo page)", async () => {
  const r = await call("GET", "/");
  return { ...r, note: `html length=${r.raw.length} chars, has form=${r.raw.includes("Check contract")}, has presets=${r.raw.includes("Mars Nexus")}` };
});

await test("GET /health", async () => {
  const r = await call("GET", "/health");
  return { ...r, note: JSON.stringify(r.data) };
});

await test("POST /check WBNB (expected SAFE)", async () => {
  const r = await call("POST", "/check", { chain: "bsc", address: WBNB });
  return { ...r, note: verdictLine(r.data) };
});

await test("POST /check Mars Nexus (real drain case)", async () => {
  const r = await call("POST", "/check", { chain: "bsc", address: MARS });
  return { ...r, note: verdictLine(r.data) };
});

await test("POST /check WBNB + unlimited approve calldata", async () => {
  const r = await call("POST", "/check", { chain: "bsc", address: WBNB, calldata: UNLIMITED_APPROVE });
  return { ...r, note: verdictLine(r.data) };
});

await test("POST /agent preflight envelope", async () => {
  const r = await call("POST", "/agent", {
    type: "preflight", task_id: "test-1", mode: "check",
    input: { address: WBNB, chain: "bsc" },
  });
  const d = r.data || {};
  return { ...r, note: `decision=${JSON.stringify(d.decision || null)} task_id=${d.task_id}` };
});

await test("POST /agent empty envelope (identity, no crash)", async () => {
  const r = await call("POST", "/agent", { type: "ping", task_id: "test-2", input: {} });
  return { ...r, note: JSON.stringify(r.data).slice(0, 400) };
});

await test("GET /check?chain=bsc&address=WBNB", async () => {
  const r = await call("GET", `/check?chain=bsc&address=${WBNB}`);
  return { ...r, note: verdictLine(r.data) };
});

await test("POST /check bad address (expect 400)", async () => {
  const r = await call("POST", "/check", { chain: "bsc", address: "0x1234" });
  return { ...r, note: JSON.stringify(r.data) };
});

console.log("\n--- SUMMARY ---");
for (const r of results) console.log(`${r.name}: status=${r.status} ms=${r.ms}`);
const failed = results.filter((r) => r.status === "ERROR" || (typeof r.status === "number" && r.status >= 500));
process.exit(failed.length ? 1 : 0);
