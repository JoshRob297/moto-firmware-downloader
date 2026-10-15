#!/usr/bin/env node

import { createInterface } from "node:readline/promises";
import { spawn } from "node:child_process";
import {
  readFileSync,
  writeFileSync,
  renameSync,
  unlinkSync,
  existsSync,
  chmodSync,
  createWriteStream,
  statSync
} from "node:fs";
import { open } from "node:fs/promises";
import { pipeline } from "node:stream/promises";
import { Readable } from "node:stream";
import { join, basename, resolve } from "node:path";
import { homedir } from "node:os";
import { lookup } from "node:dns/promises";
import { connect as tlsConnect } from "node:tls";
import {
  publicEncrypt,
  constants,
  randomUUID,
  randomBytes,
  createHash
} from "node:crypto";

const VERSION = "1.3.0";
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
  rsaPublicKey: "",
  oauthState: ""
};
const cookieJar = new Map();
let proxyStatus = { configured: false };

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
 * Network resilience layer.
 *
 * Node's global fetch (undici) collapses every transport failure into the
 * opaque string "fetch failed". The real errno (ENOTFOUND, ECONNRESET,
 * ETIMEDOUT, CERT_HAS_EXPIRED, ...) is buried in err.cause, which is why
 * users cannot self-diagnose a blocked or proxied network. These helpers
 * unwrap the cause chain, retry transient faults and emit actionable hints.
 */
const TRANSIENT_NET_CODES = new Set([
  "ECONNRESET",
  "ECONNREFUSED",
  "ETIMEDOUT",
  "EAI_AGAIN",
  "ENETUNREACH",
  "EHOSTUNREACH",
  "EPIPE",
  "UND_ERR_CONNECT_TIMEOUT",
  "UND_ERR_SOCKET",
  "UND_ERR_HEADERS_TIMEOUT",
  "UND_ERR_BODY_TIMEOUT"
]);

function unwrapNetworkError(err) {
  const seen = new Set();
  let cause = err;
  let cur = err;
  while (cur && typeof cur === "object" && !seen.has(cur)) {
    seen.add(cur);
    cause = cur;
    cur = cur.cause;
  }

  const code = String(cause?.code || err?.code || "").trim();
  const syscall = String(cause?.syscall || "").trim();
  const hostname = String(cause?.hostname || "").trim();
  const message = String(cause?.message || err?.message || "unknown transport error").trim();

  return { code, syscall, hostname, message, transient: TRANSIENT_NET_CODES.has(code) };
}

function networkHint(detail) {
  const code = detail.code.toUpperCase();
  const proxyEnv = process.env.HTTPS_PROXY || process.env.https_proxy ||
    process.env.HTTP_PROXY || process.env.http_proxy || "";

  if (code === "ENOTFOUND" || code === "EAI_AGAIN") {
    const target = detail.hostname || "lsa.lenovo.com";
    return [
      `DNS could not resolve ${target}.`,
      "Causes: ISP/regional block, corporate DNS filter, hosts file entry, VPN split-tunnel or stale DNS cache.",
      `Checks: nslookup ${target} | test with another DNS resolver | disable VPN/AV DNS filtering.`
    ].join("\n    ");
  }
  if (code === "ECONNREFUSED" || code === "ECONNRESET" || code === "EPIPE") {
    return [
      "TCP connection was refused or reset before the HTTP exchange completed.",
      "Causes: local firewall, endpoint security agent (AV/EDR) TLS inspection, or a middlebox dropping the request.",
      "Checks: allow outbound TCP 443 for node, disable HTTPS scanning temporarily, retry from a different network."
    ].join("\n    ");
  }
  if (code === "ETIMEDOUT" || code.startsWith("UND_ERR") || code === "ENETUNREACH" || code === "EHOSTUNREACH") {
    return [
      "Connection attempt timed out or the route is unreachable.",
      "Causes: silent packet drop (firewall/geo block), broken IPv6 route, or a proxy that is not being used.",
      "Checks: force IPv4, verify the route with 'mfd doctor', and retry consistently."
    ].join("\n    ");
  }
  if (/CERT|SSL|TLS|UNABLE_TO_VERIFY|SELF_SIGNED|DEPTH_ZERO/.test(code)) {
    return [
      "TLS validation failed, so something is intercepting the connection.",
      "Causes: corporate proxy MITM, expired local root CA, or a captive portal.",
      "Checks: 'mfd doctor' reports the presented certificate chain owner."
    ].join("\n    ");
  }
  if (detail.message && /proxy/i.test(detail.message)) {
    return [
      "The configured proxy rejected the connection.",
      `Detected proxy env: ${proxyEnv || "none"}`,
      "Checks: verify credentials/host of HTTPS_PROXY or unset it entirely."
    ].join("\n    ");
  }
  return [
    "No transport detail beyond the generic fetch failure was reported.",
    "Run 'mfd doctor' to isolate DNS, TCP/TLS and HTTP layers individually.",
    proxyEnv ? `Detected proxy env: ${proxyEnv}` : "No proxy environment variable detected."
  ].join("\n    ");
}

function formatNetworkFailure(url, err) {
  const detail = unwrapNetworkError(err);
  const lines = [
    "",
    "[!] NETWORK FAILURE",
    `    URL:    ${url}`,
    `    Cause:  ${detail.code || "UNKNOWN"}${detail.syscall ? ` (${detail.syscall})` : ""} - ${detail.message}`,
    "    Action:",
    `    ${networkHint(detail)}`,
    "",
    "    Run 'mfd doctor' for a full connectivity report."
  ];
  return lines.join("\n");
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

/**
 * fetch wrapper with bounded exponential backoff for transient transport faults.
 * Non-transient failures (DNS, TLS, HTTP-level) fail fast without retrying.
 */
async function fetchWithRetry(url, init = {}, options = {}) {
  const attempts = Math.max(1, Number(options.attempts) || 3);
  let lastErr;

  for (let i = 1; i <= attempts; i++) {
    try {
      return await fetch(url, init);
    } catch (err) {
      lastErr = err;
      const detail = unwrapNetworkError(err);
      if (!detail.transient || i === attempts) break;
      const backoff = 500 * 2 ** (i - 1);
      if (!options.quiet) {
        console.warn(`[!] Transient network fault (${detail.code || "unknown"}) on attempt ${i}/${attempts}, retrying in ${backoff}ms...`);
      }
      await sleep(backoff);
    }
  }

  const detail = unwrapNetworkError(lastErr);
  const wrapped = new Error(`Network failure connecting to ${url}: ${detail.code || detail.message}`);
  wrapped.cause = lastErr;
  wrapped.networkDetail = detail;
  throw wrapped;
}

/**
 * Honors standard proxy environment variables by installing an undici
 * ProxyAgent dispatcher when undici is resolvable (bundled with Node >= 18).
 * Node 24+ can alternatively be started with NODE_USE_ENV_PROXY=1.
 */
async function applyProxyFromEnv() {
  const proxy = process.env.HTTPS_PROXY || process.env.https_proxy ||
    process.env.HTTP_PROXY || process.env.http_proxy;
  if (!proxy) return { configured: false };

  try {
    const { ProxyAgent, setGlobalDispatcher } = await import("undici");
    setGlobalDispatcher(new ProxyAgent(proxy));
    return { configured: true, proxy };
  } catch (err) {
    return { configured: false, proxy, error: err.message };
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
    response = await fetchWithRetry(url, {
      method: opts.method || "POST",
      headers,
      body: isBodyAllowed ? JSON.stringify(payload) : undefined
    });
  } catch (err) {
    console.error(formatNetworkFailure(url, err));
    throw err;
  }

  updateCookies(response.headers);
  const ah = response.headers.get("Authorization");
  if (ah) session.jwt = ah;

  return response;
}

async function fetchRsaKey() {
  try {
    const r = await fetchWithRetry(API_URL + "/common/rsa.jhtml", {
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
    const detail = err.networkDetail || unwrapNetworkError(err);
    console.warn(`[!] Warning: Could not fetch daily RSA public key: ${detail.code || err.message}`);
    if (detail.code) {
      console.warn(`[!] Transport detail: ${networkHint(detail)}`);
    }
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

/**
 * Checks if a string matches an authorized session token format.
 * Accepts:
 * 1. Standard JWTs (starting with eyJ... with 3 segments)
 * 2. Native Lenovo LMSA session tokens (32-character hexadecimal MD5 hash)
 */
function isValidSessionToken(str) {
  if (typeof str !== "string") return false;
  const trimmed = str.trim();
  if (isJwt(trimmed)) return true;
  if (/^[a-fA-F0-9]{32}$/.test(trimmed)) return true;
  return false;
}

/**
 * Strict check if a string is a valid JWT token
 */
function isJwt(str) {
  if (typeof str !== "string") return false;
  const trimmed = str.trim();
  const parts = trimmed.split(".");
  return (
    parts.length === 3 &&
    parts[0].startsWith("eyJ") &&
    /^[A-Za-z0-9_-]+$/.test(parts[0]) &&
    /^[A-Za-z0-9_-]+$/.test(parts[1])
  );
}

/**
 * Exchanges OAuth authorization code for full session token
 */
async function exchangeOAuthCode(code, state) {
  const reqState = state || session.oauthState || "";
  const endpoint = `/user/oauth2/callback.jhtml?code=${encodeURIComponent(code)}&state=${encodeURIComponent(reqState)}&scope=openid`;

  try {
    const r = await apiRequest(endpoint, {}, { method: "GET", withoutAuth: true });
    const text = await r.text();

    // Check for Authorization= in text or JSON
    const m = text.match(/(?:Authorization|token)=([^&\s"<>]+)/i);
    if (m?.[1]) {
      let candidate = decodeURIComponent(m[1]).trim();
      if (candidate.startsWith("Bearer ")) candidate = candidate.slice(7).trim();
      if (isValidSessionToken(candidate)) return candidate;
    }

    try {
      const json = JSON.parse(text);
      const proto = json?.content || json?.msg || json?.desc || "";
      const m2 = proto.match(/(?:Authorization|token)=([^&\s"<>]+)/i);
      if (m2?.[1]) {
        let candidate = decodeURIComponent(m2[1]).trim();
        if (candidate.startsWith("Bearer ")) candidate = candidate.slice(7).trim();
        if (isValidSessionToken(candidate)) return candidate;
      }
    } catch {}
  } catch (err) {
    console.warn("[!] Warning: OAuth exchange request failed:", err.message);
  }
  return null;
}

/**
 * Extracts and resolves token from user input (supports URL, Code, or raw Token)
 */
async function resolveTokenInput(rawInput) {
  if (!rawInput || typeof rawInput !== "string") return null;
  let input = rawInput.trim().replace(/^["']|["']$/g, "");

  // 1. Direct Authorization token inside URI or string (e.g. softwarefix://callback?fullName=...&Authorization=35f6a...)
  const mAuth = input.match(/(?:Authorization|auth|token)=([^&\s"<>]+)/i);
  if (mAuth?.[1]) {
    let token = decodeURIComponent(mAuth[1]).trim();
    if (token.startsWith("Bearer ")) token = token.slice(7).trim();
    if (isValidSessionToken(token)) return token;
  }

  // 2. Plain Bearer token
  if (input.startsWith("Bearer ")) {
    const token = input.slice(7).trim();
    if (isValidSessionToken(token)) return token;
  }

  // 3. Raw valid session token directly pasted (32-hex LMSA token or full JWT)
  if (isValidSessionToken(input)) {
    return input;
  }

  // 4. OAuth Code inside URL: lenovoIdSuccess.html?code=...
  if (input.includes("code=") || input.includes("lenovoIdSuccess.html")) {
    try {
      const parsedUrl = new URL(input.startsWith("http") ? input : `http://localhost?${input}`);
      const code = parsedUrl.searchParams.get("code");
      const state = parsedUrl.searchParams.get("state") || session.oauthState;
      if (code) {
        console.log("[i] Detected OAuth authorization code. Exchanging for session token...");
        const exchanged = await exchangeOAuthCode(code, state);
        if (exchanged) return exchanged;
        console.warn("\n[!] The authorization code could not be exchanged with the backend.");
        console.warn("    (The browser automatically consumed the single-use code when loading lenovoIdSuccess.html).");
        console.warn("    Tip: Check your browser's Developer Tools (F12) -> Console.");
        console.warn("    Copy the full 'softwarefix://callback?...' URI printed there and paste it here.\n");
        return null;
      }
    } catch {}
  }

  // 5. Raw 33 to 128-char Hex OAuth code (attempt exchange)
  if (/^[a-fA-F0-9]{33,128}$/.test(input)) {
    console.log("[i] Detected OAuth authorization code. Exchanging with backend...");
    const exchanged = await exchangeOAuthCode(input, session.oauthState);
    if (exchanged) return exchanged;
    console.warn("\n[!] The authorization code could not be exchanged with the backend.");
    console.warn("    (The browser automatically consumed the single-use code when loading lenovoIdSuccess.html).");
    console.warn("    Tip: Check your browser's Developer Tools (F12) -> Console.");
    console.warn("    Copy the full 'softwarefix://callback?...' URI printed there and paste it here.\n");
    return null;
  }

  return null;
}

/**
 * Verify ZIP file structural integrity by reading the End of Central Directory (EOCD)
 */
async function verifyZipStructure(filePath) {
  try {
    const fileStat = statSync(filePath);
    if (fileStat.size < 22) return false;

    const readSize = Math.min(fileStat.size, 65536);
    const buffer = Buffer.alloc(readSize);
    const fh = await open(filePath, "r");
    await fh.read(buffer, 0, readSize, fileStat.size - readSize);
    await fh.close();

    const eocdSignature = Buffer.from([0x50, 0x4b, 0x05, 0x06]);
    const idx = buffer.lastIndexOf(eocdSignature);
    return idx !== -1;
  } catch {
    return false;
  }
}

/**
 * Multi-threaded / Segmented Parallel Downloader with Progress Bar
 */
async function downloadFileParallel(url, destinationPath, options = {}) {
  const { threads = 4, label = "Downloading" } = options;

  let headRes;
  try {
    headRes = await fetch(url, { method: "HEAD" });
  } catch {
    headRes = null;
  }

  const contentLength = Number(headRes?.headers?.get("content-length")) || 0;
  const acceptRanges = headRes?.headers?.get("accept-ranges") === "bytes";
  const s3Etag = headRes?.headers?.get("etag")?.replace(/["']/g, "") || "";

  // If file is small (< 15MB) or server doesn't support ranges, use standard stream
  if (!acceptRanges || contentLength < 15 * 1024 * 1024 || threads <= 1) {
    return downloadFileSingleStream(url, destinationPath, { label, s3Etag, contentLength });
  }

  const numThreads = Math.min(threads, 8);
  const chunkSize = Math.floor(contentLength / numThreads);
  const fileHandle = await open(destinationPath, "w");
  // Pre-allocate file size
  await fileHandle.truncate(contentLength);

  let totalReceived = 0;
  let lastReceived = 0;
  let lastTime = Date.now();
  let currentSpeedMBps = "0.00";

  const progressInterval = setInterval(() => {
    const now = Date.now();
    const timeDelta = (now - lastTime) / 1000;
    if (timeDelta >= 0.5) {
      const bytesDelta = totalReceived - lastReceived;
      currentSpeedMBps = (bytesDelta / (1024 * 1024 * timeDelta)).toFixed(2);
      lastReceived = totalReceived;
      lastTime = now;
    }

    if (process.stdout.isTTY) {
      const pct = ((totalReceived / contentLength) * 100).toFixed(1);
      const recMB = (totalReceived / (1024 * 1024)).toFixed(1);
      const totMB = (contentLength / (1024 * 1024)).toFixed(1);
      process.stdout.write(`\r${label} [${numThreads} threads]: ${pct}% [${recMB}MB / ${totMB}MB] @ ${currentSpeedMBps} MB/s `);
    }
  }, 250);

  try {
    const chunkPromises = [];

    for (let i = 0; i < numThreads; i++) {
      const start = i * chunkSize;
      const end = i === numThreads - 1 ? contentLength - 1 : (i + 1) * chunkSize - 1;

      chunkPromises.push((async () => {
        const res = await fetch(url, {
          headers: { Range: `bytes=${start}-${end}` }
        });

        if (!res.ok && res.status !== 206) {
          throw new Error(`Thread ${i + 1} failed: HTTP ${res.status}`);
        }

        let writeOffset = start;
        const reader = res.body.getReader();

        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          const chunkLen = value.length;
          await fileHandle.write(value, 0, chunkLen, writeOffset);
          writeOffset += chunkLen;
          totalReceived += chunkLen;
        }
      })());
    }

    await Promise.all(chunkPromises);
  } finally {
    clearInterval(progressInterval);
    await fileHandle.close();
    if (process.stdout.isTTY) process.stdout.write("\n");
  }

  // Integrity checks
  await verifyFileIntegrity(destinationPath, s3Etag);
}

/**
 * Fallback Single-Stream Downloader
 */
async function downloadFileSingleStream(url, destinationPath, options = {}) {
  const { label = "Downloading", s3Etag = "", contentLength = 0 } = options;

  const res = await fetch(url);
  if (!res.ok) throw new Error(`Download failed with status ${res.status}: ${res.statusText}`);

  const total = Number(res.headers.get("content-length")) || contentLength || 0;
  const effectiveEtag = s3Etag || res.headers.get("etag")?.replace(/["']/g, "") || "";
  let received = 0;
  let lastReceived = 0;
  let lastTime = Date.now();
  let currentSpeedMBps = "0.00";

  const nodeReadable = Readable.fromWeb(res.body);
  const hash = createHash("md5");

  nodeReadable.on("data", (chunk) => {
    received += chunk.length;
    hash.update(chunk);

    const now = Date.now();
    const timeDelta = (now - lastTime) / 1000;
    if (timeDelta >= 0.5) {
      const bytesDelta = received - lastReceived;
      currentSpeedMBps = (bytesDelta / (1024 * 1024 * timeDelta)).toFixed(2);
      lastReceived = received;
      lastTime = now;
    }

    if (total > 0 && process.stdout.isTTY) {
      const pct = ((received / total) * 100).toFixed(1);
      const mbRec = (received / 1048576).toFixed(1);
      const mbTot = (total / 1048576).toFixed(1);
      process.stdout.write(`\r${label}: ${pct}% [${mbRec}MB / ${mbTot}MB] @ ${currentSpeedMBps} MB/s `);
    }
  });

  const fileStream = createWriteStream(destinationPath);
  await pipeline(nodeReadable, fileStream);
  if (process.stdout.isTTY) process.stdout.write("\n");

  const calculatedMd5 = hash.digest("hex");
  await verifyFileIntegrity(destinationPath, effectiveEtag, calculatedMd5);
}

/**
 * Common Integrity Verification Routine
 */
async function verifyFileIntegrity(filePath, s3Etag = "", calculatedMd5 = "") {
  console.log("[i] Verifying downloaded package integrity...");

  const isZip = filePath.endsWith(".zip");
  if (isZip) {
    const zipOk = await verifyZipStructure(filePath);
    if (zipOk) {
      console.log("    [✓] ZIP archive structural test: PASSED");
    } else {
      console.warn("    [!] WARNING: ZIP structural check failed. Archive may be incomplete.");
    }
  }

  // AWS S3 single-part ETag is standard MD5
  if (s3Etag && !s3Etag.includes("-")) {
    let md5 = calculatedMd5;
    if (!md5) {
      const fileData = readFileSync(filePath);
      md5 = createHash("md5").update(fileData).digest("hex");
    }

    if (md5.toLowerCase() === s3Etag.toLowerCase()) {
      console.log(`    [✓] MD5/ETag checksum match: PASSED (${md5})`);
    } else {
      console.warn(`    [!] Checksum mismatch: (Local: ${md5} vs Remote: ${s3Etag})`);
    }
  }
}

/**
 * Live validation of session token against Motorola/Lenovo backend.
 * Returns { valid: boolean, reason?: string, status?: number, code?: string }
 */
async function validateTokenWithBackend(token) {
  const originalJwt = session.jwt;
  session.jwt = token;
  try {
    const r = await apiRequest("/query/matchParams.jhtml", { modelName: "XT2435-1" });
    const data = await parseJsonResponse(r);
    const isFailure = checkAuthFailure(r.status, data);

    if (isFailure) {
      const reason = data?.desc || data?.msg || `HTTP ${r.status}`;
      return { valid: false, reason, status: r.status, code: data?.code };
    }

    return { valid: r.ok, status: r.status, code: data?.code };
  } catch (err) {
    return { valid: false, reason: err.message };
  } finally {
    session.jwt = originalJwt;
  }
}

/**
 * Authentication Flow with Interactive Retry and Fresh Session Generation
 */
async function login() {
  if (session.jwt) {
    console.log("Notice: An active session is currently saved in", STATE_FILE);
    console.log("Proceeding with login will overwrite the existing token.\n");
  }

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
    let freshLoginRequired = true;
    let currentLoginUrl = "";

    while (true) {
      if (freshLoginRequired) {
        try {
          const r0 = await fetchWithRetry(BASE_URL + "/lmsa-web/index.jsp", { redirect: "manual" }, { attempts: 2 });
          updateCookies(r0.headers);
        } catch (err) {
          const detail = err.networkDetail || unwrapNetworkError(err);
          console.warn(`[!] Warning: Initial cookie handshake failed: ${detail.code || err.message}`);
          console.warn(`[!] Transport detail: ${networkHint(detail)}`);
        }

        await fetchRsaKey();

        const rawLoginUrl = await getLoginUrl();
        const loginUrl = new URL(rawLoginUrl);
        session.oauthState = loginUrl.searchParams.get("state") || "";
        loginUrl.searchParams.set("redirect_uri", "https://lsa.lenovo.com/Tips/lenovoIdSuccess.html");
        currentLoginUrl = loginUrl.toString();

        console.log("=======================================================");
        console.log("AUTHENTICATION");
        console.log("=======================================================");
        console.log("1. Open this FRESH URL in your web browser:\n");
        console.log(currentLoginUrl);
        console.log("\n2. Sign in with your Motorola / Lenovo account.");
        console.log("3. Once logged in, your browser will redirect to a success page or prompt");
        console.log("   to open 'softwarefix://callback?...'");
        console.log("\n   * In Firefox / Linux: Press F12 -> Console tab. Look for:");
        console.log('     Prevented navigation to "softwarefix://callback?...Authorization=<token>"');
        console.log("     Copy the entire URI or the token value and paste it below.");
        console.log("   * Important: Tokens expire in a few minutes. Please paste immediately.");
        console.log("=======================================================\n");

        openBrowser(currentLoginUrl);
        freshLoginRequired = false;
      }

      const input = await rl.question("Paste softwarefix:// URI, redirect URL, or session token (or 'new' for new link): ", { signal: ac.signal });
      const cleanInput = (input || "").trim();

      if (cleanInput.toLowerCase() === "new") {
        console.log("\n[i] Generating new fresh login session...\n");
        freshLoginRequired = true;
        continue;
      }

      const token = await resolveTokenInput(cleanInput);

      if (!token) {
        console.error("\n[!] Error: Could not extract a valid Authorization token from the input.");
        console.error("    Ensure you copy the entire 'softwarefix://callback?...' URI or the token value.");
        console.log("    Type 'new' to generate a fresh login URL, or paste again.\n");
        continue;
      }

      console.log("[i] Validating session token with Motorola backend...");
      const probe = await validateTokenWithBackend(token);

      if (!probe.valid) {
        console.warn("\n[!] Backend Validation Failed:");
        console.warn(`    Server response: ${probe.reason || "Invalid token or expired session"} (Code: ${probe.code || probe.status || "Unknown"})`);
        console.warn("    This usually happens if the link is old or the session timed out.");

        const action = await rl.question("\nOptions: [R]e-paste, [N]ew fresh login URL, [F]orce save anyway, [Q]uit: ", { signal: ac.signal });
        const act = (action || "").trim().toLowerCase();

        if (act === "n") {
          freshLoginRequired = true;
          console.log("");
          continue;
        } else if (act === "f") {
          console.log("\n[!] Force saving session token per user request...");
          session.jwt = token;
          saveState();
          console.log("Session saved to", STATE_FILE);
          break;
        } else if (act === "q") {
          process.exit(1);
        } else {
          console.log("");
          continue;
        }
      }

      session.jwt = token;
      saveState();
      console.log("\nLogin successful! Active session verified and saved to", STATE_FILE);
      break;
    }
  } finally {
    process.removeListener("SIGINT", handleSigint);
    rl.close();
  }
}

/**
 * Query firmware with specific carrier
 */
async function queryFirmwareByCarrier(modelName, imei, carrier) {
  const encryptCode = randomBytes(4).toString("hex").toUpperCase();
  const r = await apiRequest("/rescueDevice/getNewResourceByImei.jhtml", {
    imei,
    modelCode: modelName,
    roCarrier: carrier,
    encryptCode,
    sku: modelName,
    carrierSku: modelName
  });

  const data = await parseJsonResponse(r);
  if (checkAuthFailure(r.status, data)) {
    throw new Error("AUTH_EXPIRED");
  }

  if (data?.code === "0000" && Array.isArray(data?.content) && data.content.length > 0) {
    return data.content[0];
  }
  return null;
}

/**
 * Discovers available firmwares across multiple software channels
 */
async function discoverAvailableFirmwares(modelName, imei, customCarriers = []) {
  const defaultCarriers = ["retla", "reteu", "retus", "retbr", "retin", "att", "vzw", "tmo", "altmx"];
  const carriersToQuery = [...new Set([...customCarriers, ...defaultCarriers])];

  console.log(`\n[i] Querying Motorola firmware catalog for model: ${modelName} | IMEI: ${imei}...`);

  const results = [];
  const seenUris = new Set();

  const promises = carriersToQuery.map(async (carrier) => {
    try {
      const item = await queryFirmwareByCarrier(modelName, imei, carrier);
      if (item && item.romResource?.uri && !seenUris.has(item.romResource.uri)) {
        seenUris.add(item.romResource.uri);
        results.push(item);
      }
    } catch (err) {
      if (err.message === "AUTH_EXPIRED") throw err;
    }
  });

  await Promise.all(promises);
  return results;
}

/**
 * Search and Download by IMEI (Manual CLI entry point)
 */
async function searchByImei(modelName, imei, options = {}) {
  const {
    carrier = "retla",
    json = false,
    urlsOnly = false,
    download = false,
    outputDir = process.cwd(),
    threads = 4
  } = options;

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

  let item;
  try {
    item = await queryFirmwareByCarrier(modelName, imei, carrier);
  } catch (err) {
    if (err.message === "AUTH_EXPIRED") {
      console.error("\n[!] Authentication Error: Your session token is invalid or has expired.");
      console.error("[!] Please run 'mfd login' to authenticate again.\n");
      process.exit(1);
    }
    console.error("[!] Request failed:", err.message);
    process.exit(1);
  }

  if (!item) {
    if (json) {
      console.error(JSON.stringify({ error: "No firmware found for specified carrier" }, null, 2));
    } else {
      console.error(`[!] No firmware found for model '${modelName}' under carrier '${carrier}'.`);
      console.error("[!] Try specifying a different carrier (e.g. --carrier reteu, retus, retbr).");
    }
    process.exit(1);
  }

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

  displayFirmwareDetails(item);
  saveState();

  if (download) {
    await executeDownloadPipeline(item, outputDir, threads);
  }
}

function displayFirmwareDetails(item) {
  console.log("\n=======================================================");
  console.log("FIRMWARE DETAILS & OFFICIAL AWS S3 LINKS");
  console.log("=======================================================");
  console.log(`Device:         ${item.marketName || "N/A"} (${item.modelName || "N/A"})`);
  console.log(`Carrier:        ${item.carrier || "N/A"}`);
  console.log(`Platform:       ${item.platform || "N/A"}`);
  console.log(`Fingerprint OS: ${item.fingerPrint || "N/A"}`);
  console.log(`Flash Mode:     ${item.fastboot ? "Fastboot" : "BROM/EDL"}`);
  console.log("-------------------------------------------------------");
  if (item.romResource && typeof item.romResource === "object") {
    console.log(`ROM Package:    ${item.romResource.name || "N/A"}`);
    console.log(`Publish Date:   ${item.romResource.publishDate || "N/A"}`);
    console.log(`ROM Link (S3):  ${item.romResource.uri || "N/A"}\n`);
  }
  if (item.toolResource && typeof item.toolResource === "object") {
    console.log(`Tool Package:   ${item.toolResource.name || "N/A"}`);
    console.log(`Tool Link (S3): ${item.toolResource.uri || "N/A"}\n`);
  }
  if (item.flashFlow) {
    console.log(`Flash Flow:     ${item.flashFlow}\n`);
  }
  console.log("=======================================================");
}

async function executeDownloadPipeline(item, outputDir, threads = 4) {
  const targetDir = resolve(outputDir || process.cwd());

  const downloads = [];

  if (item.romResource?.uri) {
    const romFileName = item.romResource.name || basename(new URL(item.romResource.uri).pathname) || "rom.zip";
    const romDestPath = join(targetDir, romFileName);
    downloads.push({
      uri: item.romResource.uri,
      dest: romDestPath,
      name: romFileName,
      label: "Downloading ROM"
    });
  }

  if (item.toolResource?.uri) {
    const toolFileName = item.toolResource.name || basename(new URL(item.toolResource.uri).pathname) || "tool.zip";
    const toolDestPath = join(targetDir, toolFileName);
    downloads.push({
      uri: item.toolResource.uri,
      dest: toolDestPath,
      name: toolFileName,
      label: "Downloading Tools"
    });
  }

  console.log(`\nStarting accelerated parallel download into: ${targetDir}`);

  for (const dl of downloads) {
    console.log(`\n-> Package: ${dl.name}`);
    await downloadFileParallel(dl.uri, dl.dest, { threads, label: dl.label });

    const fileStat = statSync(dl.dest);
    const sizeMB = (fileStat.size / (1024 * 1024)).toFixed(2);
    const sizeGB = (fileStat.size / (1024 * 1024 * 1024)).toFixed(2);

    console.log("=======================================================");
    console.log("[✓] DOWNLOAD SAVED SUCCESSFULLY");
    console.log(`    File:     ${dl.name}`);
    console.log(`    Size:     ${fileStat.size > 1073741824 ? `${sizeGB} GB` : `${sizeMB} MB`} (${fileStat.size.toLocaleString()} bytes)`);
    console.log(`    Saved At: ${dl.dest}`);
    console.log("=======================================================");
  }
}

/**
 * Interactive Step-by-Step Wizard (All-in-One Entry Point)
 */
async function runInteractiveWizard() {
  console.log("========================================================================");
  console.log(` Moto Firmware Downloader (MFD) v${VERSION} - Interactive Wizard`);
  console.log("========================================================================");

  // 1. Session verification
  if (!session.jwt) {
    console.log("\n[!] No active session found. Initiating authentication...");
    await login();
  }

  if (!session.rsaPublicKey) {
    await fetchRsaKey();
  }

  const rl = createInterface({ input: process.stdin, output: process.stdout });
  const ac = new AbortController();

  const handleSigint = () => {
    ac.abort();
    rl.close();
    process.stdout.write("\n\nWizard cancelled by user.\n");
    process.exit(130);
  };
  process.once("SIGINT", handleSigint);

  try {
    // 2. Input Device Model
    let model = "";
    while (!model) {
      const resp = await rl.question("\n[1/4] Enter Device Model (e.g. XT2415-1, XT2435-1): ", { signal: ac.signal });
      model = resp.trim().toUpperCase();
      if (!model) console.log("Model code is required.");
    }

    // 3. Input IMEI
    let imei = "";
    while (!imei) {
      const resp = await rl.question("[2/4] Enter Device IMEI (14-15 digits): ", { signal: ac.signal });
      imei = resp.trim().replace(/\D/g, "");
      if (imei.length < 14 || imei.length > 16) {
        console.log("Invalid IMEI length. Please enter a valid 14-15 digit IMEI.");
        imei = "";
      }
    }

    // 4. Discovery & Selection
    let firmwares = [];
    try {
      firmwares = await discoverAvailableFirmwares(model, imei);
    } catch (err) {
      if (err.message === "AUTH_EXPIRED") {
        console.error("\n[!] Authentication expired. Re-authenticating...");
        await login();
        firmwares = await discoverAvailableFirmwares(model, imei);
      } else {
        throw err;
      }
    }

    if (firmwares.length === 0) {
      console.log(`\n[!] No official firmwares automatically matched for model '${model}'.`);
      const customCarrier = await rl.question("Enter a specific carrier channel to query (e.g. retla, reteu): ", { signal: ac.signal });
      if (customCarrier.trim()) {
        const item = await queryFirmwareByCarrier(model, imei, customCarrier.trim());
        if (item) firmwares.push(item);
      }
    }

    if (firmwares.length === 0) {
      console.error("\n[!] Could not locate firmware for this device. Please verify your Model and IMEI.");
      return;
    }

    // Display Available Variants
    console.log("\n========================================================================");
    console.log(`AVAILABLE OFFICIAL FIRMWARE RELEASES FOR ${model}:`);
    console.log("========================================================================");

    firmwares.forEach((fw, idx) => {
      console.log(`[${idx + 1}] Region / Carrier:  ${(fw.carrier || "DEFAULT").toUpperCase()}`);
      console.log(`    Market Name:        ${fw.marketName || "N/A"}`);
      console.log(`    Build Fingerprint:  ${fw.fingerPrint || "N/A"}`);
      console.log(`    ROM Package:        ${fw.romResource?.name || "N/A"}`);
      console.log(`    Publish Date:       ${fw.romResource?.publishDate || "N/A"}`);
      console.log(`    Flash Mode:         ${fw.fastboot ? "Fastboot" : "BROM/EDL"}`);
      console.log("------------------------------------------------------------------------");
    });
    console.log("[0] Exit");
    console.log("========================================================================");

    let selectedIndex = -1;
    while (selectedIndex < 0 || selectedIndex > firmwares.length) {
      const choice = await rl.question(`Select firmware package to use [1-${firmwares.length}]: `, { signal: ac.signal });
      const num = parseInt(choice.trim(), 10);
      if (num === 0) {
        console.log("Operation cancelled.");
        return;
      }
      if (!isNaN(num) && num >= 1 && num <= firmwares.length) {
        selectedIndex = num - 1;
      }
    }

    const selectedFirmware = firmwares[selectedIndex];

    // 5. Choose Action
    console.log("\n[3/4] Choose Action:");
    console.log("  1) High-Speed Multi-Threaded Download (Parallel Segments) [Recommended]");
    console.log("  2) Standard Single-Stream Download");
    console.log("  3) Display Direct AWS S3 Download Links");
    console.log("  4) Save Download Links to text file");

    let actionChoice = "";
    while (!["1", "2", "3", "4"].includes(actionChoice)) {
      actionChoice = (await rl.question("Select action [1-4] (default: 1): ", { signal: ac.signal })).trim() || "1";
    }

    if (actionChoice === "3") {
      displayFirmwareDetails(selectedFirmware);
      return;
    }

    if (actionChoice === "4") {
      const txtFile = join(process.cwd(), `links_${model}_${selectedFirmware.carrier || "fw"}.txt`);
      const content = [
        `Device: ${selectedFirmware.marketName} (${selectedFirmware.modelName})`,
        `Carrier: ${selectedFirmware.carrier}`,
        `Fingerprint: ${selectedFirmware.fingerPrint}`,
        `ROM Link: ${selectedFirmware.romResource?.uri || "N/A"}`,
        `Tool Link: ${selectedFirmware.toolResource?.uri || "N/A"}`
      ].join("\n");

      writeFileSync(txtFile, content, "utf8");
      console.log(`\n[✓] Links successfully exported to: ${resolve(txtFile)}`);
      return;
    }

    // 6. Output directory
    const outputPrompt = await rl.question(`\n[4/4] Output directory [default: ${process.cwd()}]: `, { signal: ac.signal });
    const targetDir = outputPrompt.trim() ? resolve(outputPrompt.trim()) : process.cwd();

    // Execute Download
    const threads = actionChoice === "1" ? 4 : 1;
    await executeDownloadPipeline(selectedFirmware, targetDir, threads);

  } finally {
    process.removeListener("SIGINT", handleSigint);
    rl.close();
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
    console.error("\n[!] Authentication Error: Your session token is invalid or has expired.");
    console.error("[!] Please run 'mfd login' to authenticate again.\n");
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

/**
 * Isolates the connectivity stack layer by layer so a user can tell a local
 * egress block apart from a backend outage without guesswork.
 */
function tlsProbe(host, port = 443, timeoutMs = 8000) {
  return new Promise((resolve) => {
    let settled = false;
    const done = (result) => {
      if (settled) return;
      settled = true;
      try { socket.destroy(); } catch {}
      resolve(result);
    };

    const socket = tlsConnect({ host, port, servername: host, timeout: timeoutMs }, () => {
      const cert = (() => {
        try { return socket.getPeerCertificate() || {}; } catch { return {}; }
      })();
      done({
        ok: Boolean(socket.authorized),
        authorizationError: socket.authorizationError ? String(socket.authorizationError) : null,
        protocol: socket.getProtocol() || null,
        cipher: socket.getCipher()?.name || null,
        alpn: socket.alpnProtocol || null,
        issuer: cert.issuer?.O || cert.issuer?.CN || null,
        subject: cert.subject?.CN || null,
        validTo: cert.valid_to || null
      });
    });

    socket.setTimeout(timeoutMs, () => done({ ok: false, error: "ETIMEDOUT" }));
    socket.on("error", (err) => done({ ok: false, error: `${err.code || err.message}` }));
  });
}

async function runDoctor(jsonOutput = false) {
  const host = new URL(BASE_URL).hostname;
  const proxyEnv = process.env.HTTPS_PROXY || process.env.https_proxy ||
    process.env.HTTP_PROXY || process.env.http_proxy || null;

  const report = {
    version: VERSION,
    runtime: { node: process.version, platform: process.platform, arch: process.arch },
    proxy: { env: proxyEnv, dispatcher: proxyStatus },
    state: { file: STATE_FILE, exists: existsSync(STATE_FILE), hasSession: Boolean(session.jwt) },
    dns: { host, addresses: [], error: null },
    tls: null,
    http: []
  };

  try {
    const records = await lookup(host, { all: true });
    report.dns.addresses = records.map((r) => `${r.address} (IPv${r.family})`);
  } catch (err) {
    const detail = unwrapNetworkError(err);
    report.dns.error = detail.code || err.message;
  }

  report.tls = report.dns.error
    ? { ok: false, error: "skipped: DNS resolution failed" }
    : await tlsProbe(host);

  const httpTargets = [
    { label: "cookie handshake (GET)", path: "/lmsa-web/index.jsp", method: "GET" },
    { label: "RSA public key (POST)", path: "/Interface/common/rsa.jhtml", method: "POST" },
    { label: "login URL dictionary (POST)", path: "/Interface/dictionary/getApiInfo.jhtml", method: "POST" }
  ];

  for (const target of httpTargets) {
    const url = BASE_URL + target.path;
    try {
      const r = await fetchWithRetry(url, {
        method: target.method,
        redirect: "manual",
        headers: { "Content-Type": "application/json", "User-Agent": USER_AGENT, "Request-Tag": "lmsa" },
        body: target.method === "POST" ? JSON.stringify({ client: { version: CLIENT_VERSION }, language: "en-US", dparams: {} }) : undefined
      }, { attempts: 2, quiet: true });
      report.http.push({ label: target.label, url, status: r.status, ok: true });
    } catch (err) {
      const detail = err.networkDetail || unwrapNetworkError(err);
      report.http.push({ label: target.label, url, ok: false, code: detail.code || null, message: detail.message });    }
  }

  if (jsonOutput) {
    console.log(JSON.stringify(report, null, 2));
    return report;
  }

  const netOk = report.http.some((e) => e.ok);
  console.log("========================================================================");
  console.log(` MFD Connectivity Doctor - v${VERSION}`);
  console.log("========================================================================");
  console.log("\n[1] Runtime");
  console.log(`    Node:     ${report.runtime.node}`);
  console.log(`    Platform: ${report.runtime.platform}/${report.runtime.arch}`);
  console.log("\n[2] Proxy");
  console.log(`    Env:        ${proxyEnv || "none"}`);
  console.log(`    Dispatcher: ${proxyStatus.configured ? `active (${proxyStatus.proxy})` : proxyStatus.error ? `FAILED to install (${proxyStatus.error})` : "direct connection"}`);
  console.log("\n[3] DNS resolution");
  if (report.dns.error) {
    console.log(`    [FAIL] ${host} -> ${report.dns.error}`);
    console.log(`    ${networkHint({ code: report.dns.error, hostname: host })}`);
  } else {
    console.log(`    [OK]   ${host} -> ${report.dns.addresses.join(", ")}`);
  }
  console.log("\n[4] TCP/TLS handshake (443)");
  if (report.tls?.ok) {
    console.log(`    [OK]   ${report.tls.protocol} / ${report.tls.cipher} / ALPN=${report.tls.alpn || "none"}`);
    console.log(`           Chain CN: ${report.tls.subject} | Issuer: ${report.tls.issuer} | Valid to: ${report.tls.validTo}`);
  } else {
    console.log(`    [FAIL] ${report.tls?.error || report.tls?.authorizationError || "unknown"}`);
    const tlsErr = String(report.tls?.authorizationError || report.tls?.error || "");
    if (tlsErr && !/^skipped/i.test(tlsErr)) {
      console.log(`    ${networkHint({ code: tlsErr, hostname: host })}`);
    }
  }
  console.log("\n[5] HTTP probes");
  for (const entry of report.http) {
    if (entry.ok) {
      console.log(`    [OK]   HTTP ${String(entry.status).padEnd(3)} ${entry.label}`);
    } else {
      console.log(`    [FAIL] ${entry.code || entry.message || "unknown"} ${entry.label}`);
    }
  }
  console.log("\n[6] Local session state");
  console.log(`    File:    ${report.state.file}`);
  console.log(`    Session: ${report.state.hasSession ? "present" : "missing (run 'mfd login')"}`);
  console.log("\n------------------------------------------------------------------------");
  if (netOk) {
    console.log("RESULT: backend reachable. If the wizard still fails, the fault is in");
    console.log("        this local network path only for specific requests (proxy, MTU).");
  } else {
    console.log("RESULT: no request reached the Lenovo backend. The fault is on the");
    console.log("        local egress path (DNS, firewall, AV/TLS inspection, proxy or");
    console.log("        an ISP/regional block). The service itself answers normally when");
    console.log("        reached over a clean route.");
  }
  console.log("------------------------------------------------------------------------");
  return report;
}

function showHelp() {
  console.log(`Moto Firmware Downloader (MFD) v${VERSION}`);
  console.log("\nUsage:");
  console.log("  mfd                                  Launch interactive guided wizard");
  console.log("  mfd login                            Authenticate with Motorola account");
  console.log("  mfd imei <Model> <IMEI> [options]    Lookup and download firmware for a device");
  console.log("  mfd search <Model> [--json]          Query required device match parameters");
  console.log("  mfd doctor [--json]                  Diagnose DNS, TCP/TLS, proxy and HTTP reachability");
  console.log("\nOptions for 'imei':");
  console.log("  -c, --carrier <Carrier>   Carrier code (default: retla)");
  console.log("  -d, --download            Directly download ROM & Tool ZIP files");
  console.log("  -o, --output <Directory>  Output directory for downloaded files");
  console.log("  -t, --threads <Number>    Number of parallel download threads (default: 4)");
  console.log("      --json                Output result in JSON format (scripting friendly)");
  console.log("      --urls-only           Print only direct downloadable S3 URLs (one per line)");
  console.log("\nGeneral Options:");
  console.log("  -h, --help                Show this help message");
  console.log("  -v, --version             Show version");
}

function parseCliArgs(argv) {
  const args = argv.slice(2);
  if (args.includes("-h") || args.includes("--help")) {
    showHelp();
    process.exit(0);
  }

  if (args.includes("-v") || args.includes("--version")) {
    console.log(`v${VERSION}`);
    process.exit(0);
  }

  if (args.length === 0 || args[0] === "wizard") {
    return { command: "wizard" };
  }

  const command = args[0];
  const rest = args.slice(1);

  if (command === "login") {
    return { command };
  }

  if (command === "doctor" || command === "diagnose") {
    return { command: "doctor", json: rest.includes("--json") };
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
    let outputDir = process.cwd();
    let threads = 4;
    const positional = [];

    for (let i = 0; i < rest.length; i++) {
      const arg = rest[i];
      if (arg === "-c" || arg === "--carrier") {
        if (!rest[i + 1] || rest[i + 1].startsWith("-")) {
          console.error("Error: --carrier requires a value.");
          process.exit(1);
        }
        carrier = rest[++i];
      } else if (arg === "-o" || arg === "--output") {
        if (!rest[i + 1] || rest[i + 1].startsWith("-")) {
          console.error("Error: --output requires a directory path.");
          process.exit(1);
        }
        outputDir = rest[++i];
      } else if (arg === "-t" || arg === "--threads") {
        if (!rest[i + 1] || isNaN(parseInt(rest[i + 1], 10))) {
          console.error("Error: --threads requires a number.");
          process.exit(1);
        }
        threads = parseInt(rest[++i], 10);
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
      console.error("Usage: mfd imei <Model> <IMEI> [--carrier <Carrier>] [--download] [-o <Dir>] [--json] [--urls-only]");
      process.exit(1);
    }

    return { command, model: positional[0], imei: positional[1], carrier, json, urlsOnly, download, outputDir, threads };
  }

  console.error(`Error: Unknown command '${command}'.`);
  showHelp();
  process.exit(1);
}

loadState();
const parsed = parseCliArgs(process.argv);

try {
  proxyStatus = await applyProxyFromEnv();

  if (parsed.command === "wizard") {
    await runInteractiveWizard();
  } else if (parsed.command === "login") {
    await login();
  } else if (parsed.command === "doctor") {
    await runDoctor(parsed.json);
  } else if (parsed.command === "imei") {
    await searchByImei(parsed.model, parsed.imei, {
      carrier: parsed.carrier,
      json: parsed.json,
      urlsOnly: parsed.urlsOnly,
      download: parsed.download,
      outputDir: parsed.outputDir,
      threads: parsed.threads
    });
  } else if (parsed.command === "search") {
    await searchParameters(parsed.model, parsed.json);
  }
} catch (err) {
  const detail = err.networkDetail || unwrapNetworkError(err);
  if (err.networkDetail) {
    console.error(formatNetworkFailure(err.message.replace(/^Network failure connecting to /, "").replace(/:.*$/, ""), err));
  } else if (detail.code) {
    console.error(`\n[!] ${err.message}\n`);
    console.error(`[!] Transport layer: ${detail.code} - ${detail.message}`);
  } else {
    console.error(`\n[!] Fatal: ${err.message}\n`);
  }
  process.exit(1);
}
