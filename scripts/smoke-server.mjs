// End-to-end smoke test against a running bitflip server.
// Exercises exactly what M0 promises: token + Origin enforcement, health payload,
// target payload, static asset serving, and SPA fallback.
//
// Usage (two terminals, or a background job for the server):
//   bitflip-cli serve <target> --no-open --port 8790 --token smoketoken123 \
//       --allow-origin http://127.0.0.1:5173
//   node scripts/smoke-server.mjs
//
// Set BITFLIP_EXPECT_DEV_ORIGIN=1 when the server was started with
// --allow-origin http://127.0.0.1:5173 (otherwise the script expects that origin
// to be rejected, which is the correct behaviour without the flag).
//
// NOTE: this script only makes HTTP requests. It never spawns the server itself --
// child_process.spawn is denied (EPERM) in this sandbox. For the "start two
// servers and check port fallback" case, use scripts/smoke-port-fallback.ps1.
import { setTimeout as sleep } from "node:timers/promises";

const BASE = "http://127.0.0.1:8790";
const TOKEN = "smoketoken123";

let failures = 0;
function check(label, condition, detail = "") {
  const mark = condition ? "PASS" : "FAIL";
  if (!condition) failures += 1;
  console.log(`  ${mark}  ${label}${detail ? ` -- ${detail}` : ""}`);
}

async function get(path, headers = {}) {
  const response = await fetch(`${BASE}${path}`, { headers, redirect: "manual" });
  const text = await response.text();
  return { status: response.status, text, type: response.headers.get("content-type") ?? "" };
}

// Wait for the server to come up.
let ready = false;
for (let i = 0; i < 60; i++) {
  try {
    const response = await fetch(`${BASE}/`);
    if (response.ok) {
      ready = true;
      break;
    }
  } catch {
    // not listening yet
  }
  await sleep(250);
}
if (!ready) {
  console.error("server never came up");
  process.exit(1);
}
console.log("server is up\n");

console.log("token enforcement");
const noToken = await get("/api/health");
check("no token -> 403", noToken.status === 403, `got ${noToken.status}`);
check("403 body is JSON with a Chinese reason", noToken.text.includes("访问令牌"), noToken.text.slice(0, 80));

const badToken = await get("/api/health", { "x-bitflip-token": "nope" });
check("wrong token -> 403", badToken.status === 403, `got ${badToken.status}`);

const headerToken = await get("/api/health", { "x-bitflip-token": TOKEN });
check("header token -> 200", headerToken.status === 200, `got ${headerToken.status}`);

const queryToken = await get(`/api/health?token=${TOKEN}`);
check("query token -> 200", queryToken.status === 200, `got ${queryToken.status}`);

console.log("\norigin enforcement");
const evilOrigin = await get("/api/health", { "x-bitflip-token": TOKEN, origin: "http://evil.example" });
check("cross-site origin -> 403", evilOrigin.status === 403, `got ${evilOrigin.status}`);
check("403 explains it was cross-site", evilOrigin.text.includes("跨站"), evilOrigin.text.slice(0, 80));

const goodOrigin = await get("/api/health", { "x-bitflip-token": TOKEN, origin: "http://127.0.0.1:8790" });
check("same-origin -> 200", goodOrigin.status === 200, `got ${goodOrigin.status}`);

const allowListed = await get("/api/health", { "x-bitflip-token": TOKEN, origin: "http://127.0.0.1:5173" });
// Only allowed when the server was started with
//   --allow-origin http://127.0.0.1:5173
// which is what the documented dev workflow does (see web/README.md). Without the
// flag this MUST be 403 -- the allow-list is explicit, never "any localhost".
if (process.env.BITFLIP_EXPECT_DEV_ORIGIN === "1") {
  check("allow-listed dev origin -> 200", allowListed.status === 200, `got ${allowListed.status}`);
} else {
  check(
    "dev origin is rejected unless --allow-origin was passed",
    allowListed.status === 403,
    `got ${allowListed.status}`,
  );
}

console.log("\nhealth payload");
const health = JSON.parse(headerToken.text);
check("ok = true", health.ok === true);
check("name_zh = 比特翻转", health.name_zh === "比特翻转", health.name_zh);
check("server_api_version = 1", health.server_api_version === 1);
check("core_api_version = 1", health.core_api_version === 1);
check("ui_embedded is a boolean", typeof health.ui_embedded === "boolean", String(health.ui_embedded));
check("target is embedded in health", health.target !== null && health.target !== undefined);
if (health.target) {
  check("target.object = pe", health.target.object === "pe", health.target.object);
  check("target.arch = x86_64/64/le", health.target.arch === "x86_64/64/le", health.target.arch);
  check("target.entry is 16 lowercase hex", /^[0-9a-f]{16}$/.test(health.target.entry ?? ""), String(health.target.entry));
}

console.log("\ntarget payload");
const target = await get("/api/target", { "x-bitflip-token": TOKEN });
check("target -> 200", target.status === 200, `got ${target.status}`);
const targetJson = JSON.parse(target.text);
check("object = pe", targetJson.object === "pe");
check("image_base is set", typeof targetJson.image_base === "string");
check("notes is an array", Array.isArray(targetJson.notes));

console.log("\nstatic assets and SPA fallback (no token required)");
const root = await get("/");
check("/ -> 200 html", root.status === 200 && root.type.startsWith("text/html"), `${root.status} ${root.type}`);
check("/ body is HTML", root.text.includes("<html"), root.text.slice(0, 60));

const deep = await get("/browse/0000000000401000");
check("deep link -> 200 html (SPA fallback)", deep.status === 200 && deep.type.startsWith("text/html"), `${deep.status} ${deep.type}`);

console.log(`\n${failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`}`);
process.exit(failures === 0 ? 0 : 1);
