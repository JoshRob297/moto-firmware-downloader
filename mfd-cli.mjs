import { createHash, randomBytes, createCipheriv } from \"node:crypto\";
import { createInterface } from \"node:readline/promises\";
import { stdin as input, stdout as output } from \"node:process\";
import { existsSync, readFileSync, writeFileSync, mkdirSync } from \"node:fs\";
import { homedir } from \"node:os\";
import { join } from \"node:path\";

const VERSION = \"1.2.4\";
const BASE_URL = \"https://lsa.lenovo.com\";
const API_URL = BASE_URL + \"/Interface\";
const USER_AGENT = \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36\";
const CLIENT_VERSION = \"7.6.2.10\";
const WINDOWS_INFO = \"Windows 11 Pro 64-bit (Build 22631)\";

const CONFIG_DIR = join(homedir(), \".mfd\");
const CONFIG_FILE = join(CONFIG_DIR, \"config.json\");

let cookieJar = new Map();
let session = {
  token: null,
  userId: null,
  email: null,
  rsaPublicKey: null
};

function serializeCookies() {
  return [...cookieJar.entries()].map(([k, v]) => `${k}=${v}`).join(\"; \");
}

function updateCookies(headers) {
  let setCookies = [];
  if (typeof headers.getSetCookie === \"function\") {
    setCookies = headers.getSetCookie();
  } else {
    const raw = headers.get(\"set-cookie\");
    if (raw) setCookies = [raw];
  }
  for (const cookieStr of setCookies) {
    const pair = cookieStr.split(\";\")[0];
    const eqIdx = pair.indexOf(\"=\");
    if (eqIdx > 0) {
      const name = pair.substring(0, eqIdx).trim();
      const val = pair.substring(eqIdx + 1).trim();
      cookieJar.set(name, val);
    }
  }
}

function formatNetworkError(url, err) {
  const cause = err.cause ? ` [Cause: ${err.cause.code || err.cause.message}]` : \"\";
  return `Network failure connecting to ${url}: ${err.message}${cause}. (Tip: Check your internet connection, DNS settings, or if an antivirus/firewall/proxy is blocking requests to Lenovo servers.)`;
}

async function apiRequest(path, body = {}, opts = {}) {
  const url = path.startsWith(\"http\") ? path : API_URL + path;
  const headers = {
    \"Content-Type\": \"application/json\",
    \"Request-Tag\": \"lmsa\",
    \"User-Agent\": USER_AGENT,
    \"Referer\": BASE_URL + \"/lmsa-web/index.jsp\"
  };

  const cookieStr = serializeCookies();
  if (cookieStr) {
    headers[\"Cookie\"] = cookieStr;
  }

  if (session.token) {
    headers[\"Authorization\"] = session.token;
    headers[\"Token\"] = session.token;
  }

  const isBodyAllowed = opts.method !== \"GET\" && opts.method !== \"HEAD\";
  const payload = {
    client: { version: CLIENT_VERSION },
    language: \"en-US\",
    windowsInfo: WINDOWS_INFO,
    ...body
  };

  let response;
  try {
    response = await fetch(url, {
      method: opts.method || \"POST\",
      headers,
      body: isBodyAllowed ? JSON.stringify(payload) : undefined
    });
  } catch (err) {
    throw new Error(formatNetworkError(url, err));
  }

  updateCookies(response.headers);

  const text = await response.text();
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    throw new Error(`Invalid JSON response from ${url}: ${text.substring(0, 150)}`);
  }

  return data;
}

async function fetchRsaKey() {
  try {
    const r = await fetch(API_URL + \"/common/rsa.jhtml\", {
      method: \"POST\",
      headers: {
        \"Content-Type\": \"application/json\",
        \"User-Agent\": USER_AGENT,
        \"Referer\": BASE_URL + \"/lmsa-web/index.jsp\"
      }
    });
    updateCookies(r.headers);
    const data = await r.json();
    if (data && data.desc) {
      session.rsaPublicKey = data.desc;
    }
  } catch (err) {
    console.warn(\"[!] Warning: Could not fetch daily RSA public key:\", err.message);
  }
}

async function getLoginUrl() {
  await fetchRsaKey();
  try {
    const data = await apiRequest(\"/dictionary/getApiInfo.jhtml\");
    if (data && data.data && data.data.loginUrl) {
      return data.data.loginUrl;
    }
  } catch (err) {
    console.warn(\"[!] Warning: Could not fetch login URL from API info:\", err.message);
  }
  return BASE_URL + \"/lmsa-web/index.jsp\";
}

async function login() {
  console.log(\"[!] Initiating authentication...\");
  const loginUrl = await getLoginUrl();
  console.log(`[!] Please authenticate via: ${loginUrl}`);
}

async function main() {
  console.log(`Moto Firmware Downloader (MFD) v${VERSION} - Interactive Wizard`);
  await login();
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch(console.error);
}
