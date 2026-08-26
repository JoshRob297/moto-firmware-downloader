import { createServer } from "node:http";
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
  jwt: "",
  rsaPublicKey: ""
};
const cookieJar = new Map();

function loadState() {
  if (!existsSync(STATE_FILE)) return;
  try {
    const data = JSON.parse(readFileSync(STATE_FILE, "utf8"));
    if (data.guid) session.guid = data.guid;
    if (data.clientUuid) session.clientUuid = data.clientUuid;
    if (data.jwt) session.jwt = data.jwt;
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
  }, null, 2));
}

function serializeCookies() {
  return [...cookieJar.entries()].map(([k, v]) => k + "=" + v).join("; ");
}

function updateCookies(headers) {
  const sc = headers.get("set-cookie");
  if (!sc) return;
  for (const line of sc.split(",")) {
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
  if (ah) session.jwt = ah.startsWith("Bearer ") ? ah : ah;
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
  throw new Error("Could not get login URL: " + JSON.stringify(data));
}

async function waitForCallback(rawLoginUrl) {
  return new Promise((resolve, reject) => {
    const server = createServer(async (req, res) => {
      const url = new URL(req.url, "http://localhost:9874");
      if (!url.searchParams.has("code")) {
        res.end("Waiting for OAuth authorization...");
        return;
      }
      res.end("<html><body><h2>Login successful. You can close this tab.</h2></body></html>");
      server.close();
      try {
        const loginUrl = new URL(rawLoginUrl);
        const state = loginUrl.searchParams.get("state") || url.searchParams.get("state") || "";
        const code = url.searchParams.get("code");
        const r = await apiRequest("/user/oauth2/callback.jhtml?code=" + code + "&state=" + state, {}, { method: "GET", withoutAuth: true });
        const text = await r.text();
        const m = text.match(/Authorization=([^&\s"<>]+)/i);
        if (m?.[1]) {
          resolve(decodeURIComponent(m[1]));
          return;
        }
        try {
          const json = JSON.parse(text);
          const proto = json?.content || json?.msg || "";
          const m2 = proto.match(/Authorization=([^&\s"<>]+)/i);
          if (m2?.[1]) {
            resolve(decodeURIComponent(m2[1]));
            return;
          }
        } catch {}
        reject(new Error("Token not found in response: " + text));
      } catch (e) {
        reject(e);
      }
    });
    server.listen(9874, "127.0.0.1", () => {
      console.log("Local OAuth callback listener active on http://127.0.0.1:9874");
    });
    setTimeout(() => {
      server.close();
      reject(new Error("OAuth login timed out after 5 minutes"));
    }, 5 * 60 * 1000);
  });
}

async function login() {
  const r0 = await fetch(BASE_URL + "/lmsa-web/index.jsp", { redirect: "manual" });
  updateCookies(r0.headers);
  await fetchRsaKey();

  const rawLoginUrl = await getLoginUrl();
  const loginUrl = new URL(rawLoginUrl);
  loginUrl.searchParams.set("redirect_uri", "https://lsa.lenovo.com/Tips/lenovoIdSuccess.html");

  console.log("\n=======================================================");
  console.log("OPEN THIS URL IN YOUR BROWSER TO AUTHENTICATE:");
  console.log(loginUrl.toString());
  console.log("=======================================================\n");

  try {
    execSync("xdg-open '" + loginUrl.toString() + "' 2>/dev/null || true");
  } catch {}

  console.log("After logging in, copy the full callback URL from your browser address bar or paste the Authorization token:");
  const token = await waitForCallback(rawLoginUrl).catch(() => null);
  
  if (token) {
    session.jwt = token.startsWith("Bearer ") ? token : token;
    saveState();
    console.log("Login successful! Session saved to", STATE_FILE);
  }
}

async function searchByImei(modelName, imei) {
  if (!session.jwt) {
    console.error("No active session found. Please run 'node mfd-cli.mjs login' first.");
    process.exit(1);
  }
  
  if (!session.rsaPublicKey) {
    await fetchRsaKey();
  }

  console.log(`\nFetching firmware for model: ${modelName} | IMEI: ${imei}...`);
  const r = await apiRequest("/rescueDevice/getNewResourceByImei.jhtml", {
    imei,
    modelCode: modelName,
    roCarrier: "retla",
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

// CLI Routing
loadState();
const command = process.argv[2];

if (command === "login") {
  await login();
} else if (command === "imei") {
  const model = process.argv[3];
  const imei = process.argv[4];
  if (!model || !imei) {
    console.error("Usage: node mfd-cli.mjs imei <Model> <IMEI>");
    console.error("Example: node mfd-cli.mjs imei XT2435-1 351234567890123");
    process.exit(1);
  }
  await searchByImei(model, imei);
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
  console.log("  node mfd-cli.mjs imei <Model> <IMEI>");
  console.log("  node mfd-cli.mjs search <Model>");
}
