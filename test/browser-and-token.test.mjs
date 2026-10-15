import test from "node:test";
import assert from "node:assert/strict";

// Mirrors the pure helpers of mfd-cli.mjs (the CLI runs side effects on import,
// so helpers are replicated here, as in token-resolver.test.mjs).

function buildBrowserOpenCommand(platform, href) {
  if (platform === "win32") {
    return { command: "explorer.exe", args: [href], fallback: { command: "rundll32.exe", args: ["url.dll,FileProtocolHandler", href] } };
  }
  if (platform === "darwin") {
    return { command: "open", args: [href] };
  }
  return { command: "xdg-open", args: [href], fallback: { command: "sensible-browser", args: [href] } };
}

function isHex32Token(str) {
  return typeof str === "string" && /^[a-fA-F0-9]{32}$/.test(str.trim());
}

function isJwtToken(str) {
  if (typeof str !== "string") return false;
  const parts = str.trim().split(".");
  return parts.length === 3 && parts[0].startsWith("eyJ");
}

function isLmsaPayload(data) {
  if (!data || typeof data !== "object" || Array.isArray(data)) return false;
  return "desc" in data || "code" in data || "msg" in data || "content" in data;
}

const OAUTH_URL = "https://passport-glb.lenovo.com/v1.0/utility/lenovoid/oauth2/authorize?state=4203d858-ee32-47c0-a791-8c4d68d4fe34&client_id=abc&response_type=code&redirect_uri=https%3A%2F%2Flsa.lenovo.com%2FTips%2FlenovoIdSuccess.html";

test("windows browser open never goes through cmd.exe (query strings survive)", () => {
  const plan = buildBrowserOpenCommand("win32", OAUTH_URL);
  assert.equal(plan.command, "explorer.exe");
  assert.equal(plan.args.length, 1);
  assert.equal(plan.args[0], OAUTH_URL);
  assert.ok(!plan.command.includes("cmd"));
  assert.ok(!plan.args.some((a) => typeof a === "string" && a.includes("start")));
});

test("windows plan passes the URL as a single argv entry (no shell re-parsing)", () => {
  const plan = buildBrowserOpenCommand("win32", OAUTH_URL);
  const joined = plan.args.join(" ");
  assert.ok(joined.includes("&client_id=abc"), "all query parameters must be preserved");
  assert.ok(joined.includes("&redirect_uri="), "redirect_uri must be preserved");
  assert.ok(!joined.includes("^&"), "no cmd-style escaping is needed once cmd.exe is out of the path");
});

test("windows fallback stays shell-free and keeps the full URL", () => {
  const plan = buildBrowserOpenCommand("win32", OAUTH_URL);
  assert.equal(plan.fallback.command, "rundll32.exe");
  assert.deepEqual(plan.fallback.args, ["url.dll,FileProtocolHandler", OAUTH_URL]);
});

test("darwin and linux plans use native openers with the raw URL", () => {
  const mac = buildBrowserOpenCommand("darwin", OAUTH_URL);
  assert.equal(mac.command, "open");
  assert.deepEqual(mac.args, [OAUTH_URL]);

  const linux = buildBrowserOpenCommand("linux", OAUTH_URL);
  assert.equal(linux.command, "xdg-open");
  assert.deepEqual(linux.args, [OAUTH_URL]);
});

test("token classification distinguishes JWT from 32-hex one-time codes", () => {
  const jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature123";
  assert.equal(isJwtToken(jwt), true);
  assert.equal(isHex32Token(jwt), false);

  const hex = "b6b1e57be14c4f2ebd3f1eb5644f99bb";
  assert.equal(isHex32Token(hex), true);
  assert.equal(isJwtToken(hex), false);

  assert.equal(isHex32Token("b6b1e57be14c4f2ebd3f1eb5644f99bb0"), false);
  assert.equal(isHex32Token("z6b1e57be14c4f2ebd3f1eb5644f99bb"), false);
});

test("isLmsaPayload separates real API answers from middlebox pages", () => {
  assert.equal(isLmsaPayload({ code: "403", desc: "Invalid token." }), true);
  assert.equal(isLmsaPayload({ code: "410", desc: "Missing device fingerprint." }), true);
  assert.equal(isLmsaPayload({ code: "0000", desc: "success", content: "x" }), true);
  assert.equal(isLmsaPayload({ error: "not found" }), false);
  assert.equal(isLmsaPayload("<html><title>HTTP Status 404 Not Found</title>"), false);
  assert.equal(isLmsaPayload(null), false);
  assert.equal(isLmsaPayload([]), false);
});
