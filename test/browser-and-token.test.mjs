import test from "node:test";
import assert from "node:assert/strict";

// Mirrors the pure helpers of mfd-cli.mjs (the CLI runs side effects on import,
// so helpers are replicated here, as in token-resolver.test.mjs).

function escapeForCmdStart(url) {
  return String(url).replace(/[&^|<>]/g, (c) => "^" + c);
}

function buildBrowserOpenCommand(platform, href, env = {}) {
  const override = (env.MFD_BROWSER || "").trim();
  if (override) {
    const parts = override.split(/\s+/).filter(Boolean);
    return { command: parts[0], args: [...parts.slice(1), href], strategy: "MFD_BROWSER override" };
  }

  if (platform === "win32") {
    return {
      command: "rundll32.exe",
      args: ["url.dll,FileProtocolHandler", href],
      strategy: "rundll32 url.dll,FileProtocolHandler",
      fallback: {
        command: "cmd.exe",
        args: ["/c", "start", "", `"${escapeForCmdStart(href)}"`],
        strategy: "cmd /c start with escaped ampersands"
      }
    };
  }
  if (platform === "darwin") {
    return { command: "open", args: [href], strategy: "open" };
  }
  return {
    command: "xdg-open",
    args: [href],
    strategy: "xdg-open",
    fallback: { command: "sensible-browser", args: [href], strategy: "sensible-browser" }
  };
}

function buildIdentity(item) {
  const rom = item?.romResource || {};
  const parts = [item?.marketName, rom.name, rom.publishDate, rom.size ?? rom.fileSize]
    .filter((v) => v !== undefined && v !== null && v !== "")
    .map(String);
  if (parts.length >= 2) return "build:" + parts.join("|").toLowerCase();
  return "uri:" + String(rom.uri || item?.toolResource?.uri || "").split("?")[0].toLowerCase();
}

function classifyDeviceId(raw) {
  if (typeof raw !== "string") return null;
  const value = raw.trim();
  if (!value) return null;

  const digitsOnly = value.replace(/[\s-]/g, "");
  if (/^\d{14,16}$/.test(digitsOnly)) return { kind: "imei", value: digitsOnly };

  if (/^[A-Za-z0-9]{6,32}$/.test(value)) return { kind: "serial", value: value.toUpperCase() };

  return null;
}

const OAUTH_URL = "https://passport-glb.lenovo.com/v1.0/utility/lenovoid/oauth2/authorize?state=4203d858-ee32-47c0-a791-8c4d68d4fe34&client_id=abc&response_type=code&redirect_uri=https%3A%2F%2Flsa.lenovo.com%2FTips%2FlenovoIdSuccess.html";

test("windows uses rundll32, not cmd or explorer (explorer opens Documents)", () => {
  const plan = buildBrowserOpenCommand("win32", OAUTH_URL, {});
  assert.equal(plan.command, "rundll32.exe");
  assert.deepEqual(plan.args, ["url.dll,FileProtocolHandler", OAUTH_URL]);
  assert.notEqual(plan.command, "explorer.exe");
  assert.notEqual(plan.command, "cmd.exe");
});

test("windows fallback escapes ampersands so cmd cannot split the URL", () => {
  const plan = buildBrowserOpenCommand("win32", OAUTH_URL, {});
  const fallbackLine = plan.fallback.args[3];
  assert.ok(fallbackLine.startsWith('"') && fallbackLine.endsWith('"'), "URL must stay quoted");
  assert.ok(!/[^?]&client_id/.test(fallbackLine.replace(/\^&/g, "")), "no bare ampersand may remain");
  assert.ok(fallbackLine.includes("^&client_id=abc"), "ampersands must be caret-escaped");
  assert.ok(fallbackLine.includes("^&redirect_uri="), "every ampersand must be escaped");
});

test("escapeForCmdStart covers the cmd metacharacters that matter", () => {
  assert.equal(escapeForCmdStart("a&b"), "a^&b");
  assert.equal(escapeForCmdStart("a|b"), "a^|b");
  assert.equal(escapeForCmdStart("a<b>c"), "a^<b^>c");
  assert.equal(escapeForCmdStart("a^b"), "a^^b");
  assert.equal(escapeForCmdStart("plain"), "plain");
});

test("MFD_BROWSER overrides the platform strategy", () => {
  const plan = buildBrowserOpenCommand("win32", OAUTH_URL, { MFD_BROWSER: "firefox --new-window" });
  assert.equal(plan.command, "firefox");
  assert.deepEqual(plan.args, ["--new-window", OAUTH_URL]);
  assert.equal(plan.strategy, "MFD_BROWSER override");
});

test("darwin and linux plans use native openers with the raw URL", () => {
  assert.equal(buildBrowserOpenCommand("darwin", OAUTH_URL, {}).command, "open");
  assert.deepEqual(buildBrowserOpenCommand("linux", OAUTH_URL, {}).args, [OAUTH_URL]);
  assert.equal(buildBrowserOpenCommand("linux", OAUTH_URL, {}).fallback.command, "sensible-browser");
});

test("buildIdentity collapses the same build served through different carriers", () => {
  const a = { marketName: "moto g", carrier: "retus", romResource: { name: "ROM_X.zip", publishDate: "2026-01-01", size: 100, uri: "https://s3/ROM_X.zip?X-Amz-Signature=aaa" } };
  const b = { marketName: "moto g", carrier: "att", romResource: { name: "ROM_X.zip", publishDate: "2026-01-01", size: 100, uri: "https://s3/ROM_X.zip?X-Amz-Signature=bbb" } };
  assert.equal(buildIdentity(a), buildIdentity(b));
});

test("buildIdentity keeps genuinely different builds apart", () => {
  const a = { romResource: { name: "ROM_X.zip", publishDate: "2026-01-01", size: 100, uri: "https://s3/a?x=1" } };
  const b = { romResource: { name: "ROM_Y.zip", publishDate: "2026-01-01", size: 100, uri: "https://s3/b?x=1" } };
  const c = { romResource: { name: "ROM_X.zip", publishDate: "2025-01-01", size: 100, uri: "https://s3/c?x=1" } };
  assert.notEqual(buildIdentity(a), buildIdentity(b));
  assert.notEqual(buildIdentity(a), buildIdentity(c));
});

test("buildIdentity falls back to the unsigned URI when build fields are missing", () => {
  const a = { romResource: { uri: "https://s3/ROM.zip?X-Amz-Signature=aaa" } };
  const b = { romResource: { uri: "https://s3/ROM.zip?X-Amz-Signature=bbb" } };
  assert.equal(buildIdentity(a), buildIdentity(b));
  assert.equal(buildIdentity(a), "uri:https://s3/rom.zip");
});

test("classifyDeviceId separates IMEIs from serial numbers", () => {
  const imei = classifyDeviceId("351234567890123");
  assert.deepEqual(imei, { kind: "imei", value: "351234567890123" });

  const imeiSpaced = classifyDeviceId("35 123456 789012 3");
  assert.equal(imeiSpaced.kind, "imei");
  assert.equal(imeiSpaced.value, "351234567890123");

  const serial = classifyDeviceId("HA1ABCDEFG");
  assert.deepEqual(serial, { kind: "serial", value: "HA1ABCDEFG" });

  const lower = classifyDeviceId("ha1abcdefg");
  assert.equal(lower.value, "HA1ABCDEFG");

  assert.equal(classifyDeviceId(""), null);
  assert.equal(classifyDeviceId("123"), null);
  assert.equal(classifyDeviceId("has spaces"), null);
  assert.equal(classifyDeviceId(null), null);
});

test("classifyDeviceId accepts the identifiers the old wizard filter destroyed", () => {
  // The old wizard stripped non-digits, so a tablet serial became an empty string
  // and an all-digit short serial was rejected without explanation.
  assert.equal(classifyDeviceId("HABCDEFG1").kind, "serial");
  assert.deepEqual(classifyDeviceId("1234567890"), { kind: "serial", value: "1234567890" });
});
