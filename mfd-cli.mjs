#!/usr/bin/env node

import { createInterface } from "node:readline/promises";
import { spawn } from "node:child_process";
import { readFileSync, writeFileSync, renameSync, unlinkSync, existsSync, chmodSync, createWriteStream } from "node:fs";
import { pipeline } from "node:stream/promises";
import { Readable } from "node:stream";
import { join, basename } from "node:path";
import { homedir } from "node:os";
import { publicEncrypt, constants, randomUUID, randomBytes } from "node:crypto";

const VERSION = "1.1.0";
const BASE_URL = "https://lsa.lenovo.com";
const API_URL = BASE_URL + "/Interface";
const USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
const CLIENT_VERSION = "7.6.2.10";
const WINDOWS_INFO = "Microsoft Windows 10 Pro, 64-bit";
const STATE_FILE = join(homedir(), ".mfd-cli-state.json");

const session = {
  guid: randomUUID(),
  clientUuid: randomUUID(),
  jwt: process.env.MFD_JWT || "",
  rsaPublicKey: ""
};
const cookieJar = new Map();

function loadState() {
  if (!existsSync(STATE_FILE)) return;
  try {
    const raw = readFileSync(STATE_FILE, "utf8");
    if (!raw.trim()) return;
    const data = JSON.parse(raw);
    if (typeof data !== "object" || data === null) return;

    if (data.guid) session.guid = data.guid;
    if (data.clientUuid) session.clientUuid = data.clientUuid;
    if (data.jwt && !session.jwt) session.jwt = data.jwt;
    if (data.rsaPublicKey) session.rsaPublicKey = data.rsaPublicKey;
    if (data.cookies && typeof data.cookies === "object") {
      for (const [k, v] of Object.entries(data.cookies)) {
        if (typeof k === "string" && typeof v === "string") {
          cookieJar.set(k, v);
        }
      }
    }
  } catch (err) {
    console.warn(`[!] Warning: Could not read state from ${STATE_FILE}: ${err.message}`);
  }
}

function saveState() {
  const tmpFile = `${STATE_FILE}.tmp.${process.pid}.${Date.now()}`;
  try {
    const payload = JSON.stringify({
      guid: session.guid,
      clientUuid: session.clientUuid,
      jwt: session.jwt,
      rsaPublicKey: session.rsaPublicKey,
      cookies: Object.fromEntries(cookieJar.entries())
    }, null, 2);

    writeFileSync(tmpFile, payload, { mode: 0o600, encoding: "utf8" });
    try {
      chmodSync(tmpFile, 0o600);
    } catch {}
    renameSync(tmpFile, STATE_FILE);
    try {
      chmodSync(STATE_FILE, 0o600);
    } catch {}
  } catch (err) {
    console.error(`[!] Failed to save state to ${STATE_FILE}:`, err.message);
    try {
      if (existsSync(tmpFile)) unlinkSync(tmpFile);
    } catch {}
  }
}

function serializeCookies() {
  return [...cookieJar.entries()].map(([k, v]) => `${k}=${v}`).join("; ");
}

function updateCookies(headers) {
  let setCookies = [];
  if (typeof headers.getSetCookie === "function") {
    setCookies = headers.getSetCookie();
  } else {
    const sc = headers.get("set-cookie");
    if (sc) {
      setCookies = sc.split(/,(?=[^;,]+=[^;,]+)/);
    }
  }

  for (const line of setCookies) {
    const pair = line.split(";")[0].trim();
    const eq = pair.indexOf("=");
    if (eq > 0) {
      const k = pair.slice(0, eq).trim();
      const v = pair.slice(eq + 1).trim();
      if (k && v) cookieJar.set(k, v);
    }
  }
}

function getLastSegmentForLog(url) {
  try {
    const parsed = new URL(url);
    const parts = parsed.pathname.split("/");
    const last = parts[parts.length - 1] || "";
    const dotIdx = last.lastIndexOf(".");
    const name = dotIdx > 0 ? last.substring(0, dotIdx) : last;
    return `${name}interface`;
  } catch {
    return "interface";
  }
}

/**
 * Generates the X-Device-Fingerprint HTTP header required by Motorola RSA API.
 * Reverse engineered from webservices.dll by JoshRob.
 */
function createClientRequestFinger(url, authToken, serverPublicKeyBase64) {
  if (!authToken || !serverPublicKeyBase64) return null;
  try {
    const ts = Date.now().toString();
    const segment = getLastSegmentForLog(url);
    const plain = `${ts}|${authToken}|${segment}`;

    const derBuf = Buffer.from(serverPublicKeyBase64.trim(), "base64");
    if (derBuf.length === 0) return null;

    const pem = `-----BEGIN PUBLIC KEY-----\n${derBuf.toString("base64").match(/.{1,64}/g).join("\n")}\n-----END PUBLIC KEY-----`;

    const encrypted = publicEncrypt({
      key: pem,
      padding: constants.RSA_PKCS1_PADDING
    }, Buffer.from(plain, "utf8"));

    return encrypted.toString("base64");
  } catch (err) {
    console.warn("[!] Warning: Failed to compute request fingerprint:", err.message);
    return null;
  }
}

async function parseJsonResponse(response) {
  const text = await response.text();
  try {
    return JSON.parse(text);
  } catch {
    const preview = text.slice(0, 150).replace(/\s+/g, " ").trim();
    throw new Error(`Invalid JSON response (HTTP ${response.status} ${response.statusText}): "${preview}..."`);
  }
}

function checkAuthFailure(status, data) {
  const isAuthHttp = status === 401 || status === 403;
  const isAuthBodyCode = data?.code === "1001" || data?.code === "401" || data?.code === "403" ||
    (typeof data?.msg === "string" && /token|auth|session|expired|unauthorized/i.test(data.msg));

  if (isAuthHttp || isAuthBodyCode) {
    console.error("\n[!] Authentication Error: Your session token is invalid or has expired.");
    console.error("[!] Please run 'mfd login' (or 'node mfd-cli.mjs login') to authenticate again.\n");
    return true;
  }
  return false;
}

async function apiRequest(path, body = {}, opts = {}) {
  const url = path.startsWith("http") ? path : API_URL + path;
  const headers = {
    "Content-Type": "application/json",
    "Request-Tag": "lmsa",
    "User-Agent": USER_AGENT,
    "Guid": session.guid,
    "clientUUID": session.clientUuid,
    "clientVersion": CLIENT_VERSION,
    "language": "en-US",
    "windowsInfo": Buffer.from(WINDOWS_INFO).toString("base64"),
    "Cookie": serializeCookies()
  };

  if (!opts.withoutAuth && session.jwt) {
    headers["Authorization"] = session.jwt;
    const fp = createClientRequestFinger(url, session.jwt, session.rsaPublicKey);
    if (fp) headers["X-Device-Fingerprint"] = fp;
  }

  const isBodyAllowed = opts.method !== "GET" && opts.method !== "HEAD";
  const payload = {
    client: { version: CLIENT_VERSION },
    language: "en-US",
    windowsInfo: WINDOWS_INFO,
    dparams: body
  };

  let response;
  try {
    response = await fetch(url, {
      method: opts.method || "POST",
      headers,
      body: isBodyAllowed ? JSON.stringify(payload) : undefined
    });
  } catch (err) {
    throw new Error(`Network failure connecting to ${url}: ${err.message}`);
  }

  updateCookies(response.headers);
  const ah = response.headers.get("Authorization");
  if (ah) session.jwt = ah;

  return response;
}

async function fetchRsaKey() {
  try {
    const r = await fetch(API_URL + "/common/rsa.jhtml", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Request-Tag": "lmsa",
        "User-Agent": USER_AGENT,
      },
      body: JSON.stringify({ client: { version: CLIENT_VERSION }, language: "en-US", dparams: {} })
    });

    if (!r.ok) {
      console.warn(`[!] Warning: RSA endpoint returned HTTP ${r.status} ${r.statusText}`);
      return;
    }

    const data = await parseJsonResponse(r);
    if (data?.desc && data.desc.length > 20) {
      session.rsaPublicKey = data.desc;
    }
  } catch (err) {
    console.warn("[!] Warning: Could not fetch daily RSA public key:", err.message);
  }
}

async function getLoginUrl() {
  const r = await apiRequest("/dictionary/getApiInfo.jhtml", { key: "TIP_URL" }, { withoutAuth: true });
  if (!r.ok) {
    throw new Error(`Failed to fetch login URL (HTTP ${r.status} ${r.statusText})`);
  }

  const data = await parseJsonResponse(r);
  const content = data?.content || data?.msg || "";
  if (typeof content === "string" && content.startsWith("http")) return content;
  if (typeof content === "string") {
    try {
      const p = JSON.parse(content);
      if (p?.login_url) return p.login_url;
    } catch {}
  }
  throw new Error("Could not retrieve login URL: " + JSON.stringify(data));
}

function openBrowser(targetUrl) {
  try {
    const parsed = new URL(targetUrl);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return;

    if (process.platform === "win32") {
      spawn("cmd.exe", ["/c", "start", '""', parsed.href], { stdio: "ignore", detached: true }).unref();
    } else if (process.platform === "darwin") {
      spawn("open", [parsed.href], { stdio: "ignore", detached: true }).unref();
    } else {
      spawn("xdg-open", [parsed.href], { stdio: "ignore", detached: true }).unref();
    }
  } catch {}
}

function extractToken(rawInput) {
  if (!rawInput || typeof rawInput !== "string") return null;
  let input = rawInput.trim().replace(/^["']|["']$/g, "");

  const m = input.match(/(?:Authorization|token|auth)=([^&\s"<>]+)/i);
  if (m?.[1]) {
    let raw = m[1].trim();
    try {
      raw = decodeURIComponent(raw);
    } catch {}
    if (raw.startsWith("Bearer ")) raw = raw.slice(7).trim();
    return raw;
  }

  if (input.startsWith("Bearer ")) {
    input = input.slice(7).trim();
  }

  if (/^[a-zA-Z0-9_.-]{16,4096}$/.test(input)) {
    return input;
  }

  return null;
}

async function downloadFile(url, destinationPath) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`Download failed with status ${res.status}: ${res.statusText}`);
  const total = Number(res.headers.get("content-length")) || 0;
  let received = 0;

  const nodeReadable = Readable.fromWeb(res.body);
  nodeReadable.on("data", (chunk) => {
    received += chunk.length;
    if (total > 0 && process.stdout.isTTY) {
      const pct = ((received / total) * 100).toFixed(1);
      const mbRec = (received / 1048576).toFixed(1);
      const mbTot = (total / 1048576).toFixed(1);
      process.stdout.write(`\rDownloading: ${pct}% [${mbRec}MB / ${mbTot}MB]`);
    }
  });

  const fileStream = createWriteStream(destinationPath);
  await pipeline(nodeReadable, fileStream);
  if (process.stdout.isTTY) process.stdout.write("\n");
}

async function login() {
  if (session.jwt) {
    console.log("Notice: An active session is currently saved in", STATE_FILE);
    console.log("Proceeding with login will overwrite the existing token.\n");
  }

  try {
    const r0 = await fetch(BASE_URL + "/lmsa-web/index.jsp", { redirect: "manual" });
    updateCookies(r0.headers);
  } catch (err) {
    console.warn("[!] Warning: Initial cookie handshake failed:", err.message);
  }

  await fetchRsaKey();

  const rawLoginUrl = await getLoginUrl();
  const loginUrl = new URL(rawLoginUrl);
  loginUrl.searchParams.set("redirect_uri", "https://lsa.lenovo.com/Tips/lenovoIdSuccess.html");

  console.log("=======================================================");
  console.log("AUTHENTICATION");
  console.log("=======================================================");
  console.log("1. Open this URL in your web browser:\n");
  console.log(loginUrl.toString());
  console.log("\n2. Log in with your Motorola account.");
  console.log("3. When redirection completes, copy the full URL from your address bar (or the Authorization parameter value).");
  console.log("=======================================================\n");

  openBrowser(loginUrl.toString());

  const rl = createInterface({ input: process.stdin, output: process.stdout });
  const ac = new AbortController();

  const handleSigint = () => {
    ac.abort();
    rl.close();
    process.stdout.write("\n\nLogin aborted by user.\n");
    process.exit(130);
  };
  process.once("SIGINT", handleSigint);

  try {
    const input = await rl.question("Paste the redirect URL or Authorization token here: ", { signal: ac.signal });
    const token = extractToken(input);

    if (!token) {
      console.error("\nError: Could not extract a valid Authorization token from the provided input.");
      process.exit(1);
    }

    session.jwt = token;
    saveState();
    console.log("\nLogin successful! Session saved to", STATE_FILE);
  } finally {
    process.removeListener("SIGINT", handleSigint);
    rl.close();
  }
}

async function searchByImei(modelName, imei, options = {}) {
  const { carrier = "retla", json = false, urlsOnly = false, download = false } = options;

  if (!session.jwt) {
    console.error("Error: No active session found. Please run 'mfd login' or set MFD_JWT.");
    process.exit(1);
  }

  if (!session.rsaPublicKey) {
    await fetchRsaKey();
  }

  if (!json && !urlsOnly) {
    console.log(`\nFetching firmware for model: ${modelName} | IMEI: ${imei} | Carrier: ${carrier}...`);
  }

  const encryptCode = randomBytes(4).toString("hex").toUpperCase();

  let r;
  try {
    r = await apiRequest("/rescueDevice/getNewResourceByImei.jhtml", {
      imei,
      modelCode: modelName,
      roCarrier: carrier,
      encryptCode,
      sku: modelName,
      carrierSku: modelName
    });
  } catch (err) {
    console.error("[!] Request failed:", err.message);
    process.exit(1);
  }

  let data;
  try {
    data = await parseJsonResponse(r);
  } catch (err) {
    console.error(`[!] API Error: ${err.message}`);
    process.exit(1);
  }

  if (checkAuthFailure(r.status, data)) {
    process.exit(1);
  }

  if (!r.ok) {
    console.error(`[!] API returned HTTP ${r.status} ${r.statusText}:`, JSON.stringify(data, null, 2));
    process.exit(1);
  }

  if (data?.code !== "0000" || !Array.isArray(data?.content) || data.content.length === 0) {
    if (json) {
      console.error(JSON.stringify(data, null, 2));
    } else {
      console.error("API response error:", JSON.stringify(data, null, 2));
    }
    process.exit(1);
  }

  const item = data.content[0] || {};

  if (json) {
    console.log(JSON.stringify(item, null, 2));
    saveState();
    return;
  }

  if (urlsOnly) {
    if (item.romResource?.uri) console.log(item.romResource.uri);
    if (item.toolResource?.uri) console.log(item.toolResource.uri);
    saveState();
    return;
  }

  console.log("\n=======================================================");
  console.log("FIRMWARE DETAILS AND DOWNLOAD LINKS");
  console.log("=======================================================");
  console.log(`Device:         ${item.marketName || "N/A"} (${item.modelName || "N/A"})`);
  console.log(`Carrier:        ${item.carrier || "N/A"}`);
  console.log(`Platform:       ${item.platform || "N/A"}`);
  console.log(`Fingerprint OS: ${item.fingerPrint || "N/A"}`);
  console.log(`Flash Mode:     ${item.fastboot ? "Fastboot" : "BROM/EDL"}`);
  console.log("-------------------------------------------------------");
  if (item.romResource && typeof item.romResource === "object") {
    console.log(`ROM ZIP:        ${item.romResource.name || "N/A"}`);
    console.log(`Publish Date:   ${item.romResource.publishDate || "N/A"}`);
    console.log(`ROM Link (S3):  ${item.romResource.uri || "N/A"}\n`);
  }
  if (item.toolResource && typeof item.toolResource === "object") {
    console.log(`Tool ZIP:       ${item.toolResource.name || "N/A"}`);
    console.log(`Tool Link (S3): ${item.toolResource.uri || "N/A"}\n`);
  }
  if (item.flashFlow) {
    console.log(`Flash Flow:     ${item.flashFlow}\n`);
  }
  console.log("=======================================================");
  saveState();

  if (download) {
    if (item.romResource?.uri) {
      const fileName = item.romResource.name || basename(new URL(item.romResource.uri).pathname) || "rom.zip";
      console.log(`\nStarting download for ${fileName}...`);
      await downloadFile(item.romResource.uri, join(process.cwd(), fileName));
      console.log(`Saved: ${fileName}`);
    }
    if (item.toolResource?.uri) {
      const toolName = item.toolResource.name || basename(new URL(item.toolResource.uri).pathname) || "tool.zip";
      console.log(`\nStarting download for ${toolName}...`);
      await downloadFile(item.toolResource.uri, join(process.cwd(), toolName));
      console.log(`Saved: ${toolName}`);
    }
  }
}

async function searchParameters(modelName, json = false) {
  if (!session.jwt) {
    console.error("Error: No active session found. Run 'mfd login' first.");
    process.exit(1);
  }
  if (!session.rsaPublicKey) {
    await fetchRsaKey();
  }

  if (!json) {
    console.log(`\nQuerying match parameters for: ${modelName}...`);
  }

  let r;
  try {
    r = await apiRequest("/rescueDevice/getRomMatchParams.jhtml", { modelName });
  } catch (err) {
    console.error("[!] Request failed:", err.message);
    process.exit(1);
  }

  let data;
  try {
    data = await parseJsonResponse(r);
  } catch (err) {
    console.error(`[!] API Error: ${err.message}`);
    process.exit(1);
  }

  if (checkAuthFailure(r.status, data)) {
    process.exit(1);
  }

  if (!r.ok) {
    console.error(`[!] API returned HTTP ${r.status} ${r.statusText}:`, JSON.stringify(data, null, 2));
    process.exit(1);
  }

  if (json) {
    console.log(JSON.stringify(data?.content || data, null, 2));
  } else {
    console.log("Required Parameters:", JSON.stringify(data?.content, null, 2));
  }
}

function showHelp() {
  console.log(`Moto Firmware Downloader (MFD) v${VERSION}`);
  console.log("\nUsage:");
  console.log("  mfd login");
  console.log("  mfd imei <Model> <IMEI> [options]");
  console.log("  mfd search <Model> [--json]");
  console.log("\nOptions for 'imei':");
  console.log("  -c, --carrier <Carrier>   Carrier code (default: retla)");
  console.log("  -d, --download            Directly download ROM & Tool ZIP files to current directory");
  console.log("      --json                Output result in JSON format (scripting friendly)");
  console.log("      --urls-only           Print only direct downloadable S3 URLs (one per line)");
  console.log("\nGeneral Options:");
  console.log("  -h, --help                Show this help message");
  console.log("  -v, --version             Show version");
}

function parseCliArgs(argv) {
  const args = argv.slice(2);
  if (args.length === 0 || args.includes("-h") || args.includes("--help")) {
    showHelp();
    process.exit(0);
  }

  if (args.includes("-v") || args.includes("--version")) {
    console.log(`v${VERSION}`);
    process.exit(0);
  }

  const command = args[0];
  const rest = args.slice(1);

  if (command === "login") {
    return { command };
  }

  if (command === "search") {
    const json = rest.includes("--json");
    const positional = rest.filter((a) => !a.startsWith("-"));
    if (!positional[0]) {
      console.error("Error: Missing required argument <Model>.\nUsage: mfd search <Model> [--json]");
      process.exit(1);
    }
    return { command, model: positional[0], json };
  }

  if (command === "imei") {
    let carrier = "retla";
    let json = false;
    let urlsOnly = false;
    let download = false;
    const positional = [];

    for (let i = 0; i < rest.length; i++) {
      const arg = rest[i];
      if (arg === "-c" || arg === "--carrier") {
        if (!rest[i + 1] || rest[i + 1].startsWith("-")) {
          console.error("Error: --carrier requires a value.");
          process.exit(1);
        }
        carrier = rest[++i];
      } else if (arg === "--json") {
        json = true;
      } else if (arg === "--urls-only") {
        urlsOnly = true;
      } else if (arg === "-d" || arg === "--download") {
        download = true;
      } else if (arg.startsWith("-")) {
        console.error(`Error: Unknown flag '${arg}'`);
        process.exit(1);
      } else {
        positional.push(arg);
      }
    }

    if (positional.length < 2) {
      console.error("Error: Missing required arguments <Model> and <IMEI>.");
      console.error("Usage: mfd imei <Model> <IMEI> [--carrier <Carrier>] [--download] [--json] [--urls-only]");
      process.exit(1);
    }

    return { command, model: positional[0], imei: positional[1], carrier, json, urlsOnly, download };
  }

  console.error(`Error: Unknown command '${command}'.`);
  showHelp();
  process.exit(1);
}

loadState();
const parsed = parseCliArgs(process.argv);

if (parsed.command === "login") {
  await login();
} else if (parsed.command === "imei") {
  await searchByImei(parsed.model, parsed.imei, {
    carrier: parsed.carrier,
    json: parsed.json,
    urlsOnly: parsed.urlsOnly,
    download: parsed.download
  });
} else if (parsed.command === "search") {
  await searchParameters(parsed.model, parsed.json);
}
