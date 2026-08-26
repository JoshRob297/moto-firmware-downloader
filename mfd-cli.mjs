#!/usr/bin/env node

import { createInterface } from "node:readline/promises";
import { execSync } from "node:child_process";
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import { publicEncrypt, constants } from "node:crypto";

const BASE_URL = "https://lsa.lenovo.com";
const API_URL = BASE_URL + "/Interface";
const USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
const CLIENT_VERSION = "7.6.2.10";
const WINDOWS_INFO = "Microsoft Windows 10 Pro, 64-bit";
const STATE_FILE = join(homedir(), ".mfd-cli-state.json");

const session = {
  guid: crypto.randomUUID(),
  clientUuid: crypto.randomUUID(),
  jwt: process.env.MFD_JWT || "",
  rsaPublicKey: ""
};
const cookieJar = new Map();

function loadState() {
  if (!existsSync(STATE_FILE)) return;
  try {
    const data = JSON.parse(readFileSync(STATE_FILE, "utf8"));
    if (data.guid) session.guid = data.guid;
    if (data.clientUuid) session.clientUuid = data.clientUuid;
    if (data.jwt && !session.jwt) session.jwt = data.jwt;
    if (data.rsaPublicKey) session.rsaPublicKey = data.rsaPublicKey;
    if (data.cookies) {
      for (const [k, v] of Object.entries(data.cookies)) {
        cookieJar.set(k, v);
      }
    }
  } catch {}
}

function saveState() {
  writeFileSync(STATE_FILE, JSON.stringify({
    guid: session.guid,
    clientUuid: session.clientUuid,
    jwt: session.jwt,
    rsaPublicKey: session.rsaPublicKey,
    cookies: Object.fromEntries(cookieJar.entries())
  }, null, 2), { mode: 0o600, encoding: "utf8" });
}

function serializeCookies() {
  return [...cookieJar.entries()].map(([k, v]) => k + "=" + v).join("; ");
}

function updateCookies(headers) {
  // Use getSetCookie if available (Node 18.14.0+) or split fallback
  let setCookies = [];
  if (typeof headers.getSetCookie === "function") {
    setCookies = headers.getSetCookie();
  } else {
    const sc = headers.get("set-cookie");
    if (sc) {
      // Split by comma only when followed by a cookie-name= (not inside dates like 'Expires=Wed, 21 Oct')
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
  const parts = url.split('/');
  const last = parts[parts.length - 1];
  const dotIdx = last.lastIndexOf('.');
  const name = dotIdx > 0 ? last.substring(0, dotIdx) : last;
  return name + "interface";
}

/**
 * Generates the X-Device-Fingerprint HTTP header required by Motorola RSA API.
 * Reverse engineered from webservices.dll by JoshRob.
 */
function createClientRequestFinger(url, authToken, serverPublicKeyBase64) {
  if (!authToken || !serverPublicKeyBase64) return null;
  const ts = Date.now().toString();
  const segment = getLastSegmentForLog(url);
  const plain = `${ts}|${authToken}|${segment}`;
  
  const derBuf = Buffer.from(serverPublicKeyBase64, "base64");
  const pem = `-----BEGIN PUBLIC KEY-----\n${derBuf.toString("base64").match(/.{1,64}/g).join("\n")}\n-----END PUBLIC KEY-----`;
  
  const encrypted = publicEncrypt({
    key: pem,
    padding: constants.RSA_PKCS1_PADDING
  }, Buffer.from(plain, 'utf8'));
  
  return encrypted.toString('base64');
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
    const data = await r.json();
    if (data?.desc && data.desc.length > 20) {
      session.rsaPublicKey = data.desc;
    }
  } catch (err) {
    console.warn("Warning: Could not fetch daily RSA public key:", err.message);
  }
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
  
  const payload = {
    client: { version: CLIENT_VERSION },
    language: "en-US",
    windowsInfo: WINDOWS_INFO,
    dparams: body
  };
  
  const r = await fetch(url, {
    method: opts.method || "POST",
    headers,
    body: method_has_body(opts.method) ? JSON.stringify(payload) : undefined
  });
  updateCookies(r.headers);
  const ah = r.headers.get("Authorization");
  if (ah) session.jwt = ah;
  return r;
}

function method_has_body(method) {
  return method !== "GET" && method !== "HEAD";
}

async function getLoginUrl() {
  const r = await apiRequest("/dictionary/getApiInfo.jhtml", { key: "TIP_URL" }, { withoutAuth: true });
  const data = await r.json();
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

function openBrowser(url) {
  try {
    const platform = process.platform;
    if (platform === "win32") {
      execSync(`start "" "${url}"`, { stdio: "ignore" });
    } else if (platform === "darwin") {
      execSync(`open "${url}"`, { stdio: "ignore" });
    } else {
      execSync(`xdg-open "${url}" 2>/dev/null || true`, { stdio: "ignore" });
    }
  } catch {}
}

function extractToken(input) {
  if (!input) return null;
  input = input.trim();
  
  // URL parameter matching: Authorization=... or token=... or auth=...
  const m = input.match(/(?:Authorization|token|auth)=([^&\s"<>]+)/i);
  if (m?.[1]) {
    let token = decodeURIComponent(m[1]).trim();
    if (token.startsWith("Bearer ")) token = token.slice(7).trim();
    return token;
  }
  
  // Plain Bearer string: "Bearer eyJhbG..." or "Bearer abc123..."
  if (input.startsWith("Bearer ")) {
    input = input.slice(7).trim();
  }
  
  // Raw token (JWT with dots, base64, hex or alphanumerics)
  if (/^[a-zA-Z0-9_.-]{16,4096}$/.test(input)) {
    return input;
  }
  
  return null;
}

async function login() {
  if (session.jwt) {
    console.log("Notice: An active session is currently saved in", STATE_FILE);
    console.log("Proceeding with login will overwrite the existing token.\n");
  }

  const r0 = await fetch(BASE_URL + "/lmsa-web/index.jsp", { redirect: "manual" });
  updateCookies(r0.headers);
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
  try {
    const input = await rl.question("Paste the redirect URL or Authorization token here: ");
    const token = extractToken(input);
    
    if (!token) {
      console.error("\nError: Could not extract a valid Authorization token from the provided input.");
      process.exit(1);
    }
    
    session.jwt = token;
    saveState();
    console.log("\nLogin successful! Session saved to", STATE_FILE);
  } finally {
    rl.close();
  }
}

async function searchByImei(modelName, imei, carrier = "retla") {
  if (!session.jwt) {
    console.error("No active session found. Please run 'node mfd-cli.mjs login' or set MFD_JWT environment variable first.");
    process.exit(1);
  }
  
  if (!session.rsaPublicKey) {
    await fetchRsaKey();
  }

  console.log(`\nFetching firmware for model: ${modelName} | IMEI: ${imei} | Carrier: ${carrier}...`);
  const r = await apiRequest("/rescueDevice/getNewResourceByImei.jhtml", {
    imei,
    modelCode: modelName,
    roCarrier: carrier,
    encryptCode: Math.random().toString(36).slice(2, 10).toUpperCase(),
    sku: modelName,
    carrierSku: modelName
  });
  
  const data = await r.json();
  if (data?.code !== "0000" || !data?.content || data.content.length === 0) {
    console.error("API response error:", JSON.stringify(data, null, 2));
    return;
  }
  
  const item = data.content[0];
  console.log("\n=======================================================");
  console.log("FIRMWARE DETAILS AND DOWNLOAD LINKS");
  console.log("=======================================================");
  console.log(`Device:         ${item.marketName} (${item.modelName})`);
  console.log(`Carrier:        ${item.carrier}`);
  console.log(`Platform:       ${item.platform}`);
  console.log(`Fingerprint OS: ${item.fingerPrint}`);
  console.log(`Flash Mode:     ${item.fastboot ? 'Fastboot' : 'BROM/EDL'}`);
  console.log("-------------------------------------------------------");
  if (item.romResource) {
    console.log(`ROM ZIP:        ${item.romResource.name}`);
    console.log(`Publish Date:   ${item.romResource.publishDate || 'N/A'}`);
    console.log(`ROM Link (S3):  ${item.romResource.uri}\n`);
  }
  if (item.toolResource) {
    console.log(`Tool ZIP:       ${item.toolResource.name}`);
    console.log(`Tool Link (S3): ${item.toolResource.uri}\n`);
  }
  if (item.flashFlow) {
    console.log(`Flash Flow:     ${item.flashFlow}\n`);
  }
  console.log("=======================================================");
  saveState();
}

async function searchParameters(modelName) {
  if (!session.jwt) {
    console.error("No active session found. Please run 'node mfd-cli.mjs login' first.");
    process.exit(1);
  }
  if (!session.rsaPublicKey) {
    await fetchRsaKey();
  }
  console.log(`\nQuerying match parameters for: ${modelName}...`);
  const r = await apiRequest("/rescueDevice/getRomMatchParams.jhtml", { modelName });
  const data = await r.json();
  console.log("Required Parameters:", JSON.stringify(data?.content, null, 2));
}

function parseImeiArgs(args) {
  let carrier = "retla";
  const positional = [];
  
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--carrier" || args[i] === "-c") {
      if (args[i + 1]) {
        carrier = args[i + 1];
        i++;
      }
    } else {
      positional.push(args[i]);
    }
  }
  
  return {
    model: positional[0],
    imei: positional[1],
    carrier
  };
}

// CLI Routing
loadState();
const command = process.argv[2];

if (command === "login") {
  await login();
} else if (command === "imei") {
  const { model, imei, carrier } = parseImeiArgs(process.argv.slice(3));
  if (!model || !imei) {
    console.error("Usage: node mfd-cli.mjs imei <Model> <IMEI> [--carrier <Carrier>]");
    console.error("Example: node mfd-cli.mjs imei XT2435-1 351234567890123 --carrier retla");
    process.exit(1);
  }
  await searchByImei(model, imei, carrier);
} else if (command === "search") {
  const model = process.argv[3];
  if (!model) {
    console.error("Usage: node mfd-cli.mjs search <Model>");
    process.exit(1);
  }
  await searchParameters(model);
} else {
  console.log("Moto Firmware Downloader (MFD)");
  console.log("Usage:");
  console.log("  node mfd-cli.mjs login");
  console.log("  node mfd-cli.mjs imei <Model> <IMEI> [--carrier <Carrier>]");
  console.log("  node mfd-cli.mjs search <Model>");
  console.log("\nOptions:");
  console.log("  --carrier, -c   Carrier code (default: retla)");
}
