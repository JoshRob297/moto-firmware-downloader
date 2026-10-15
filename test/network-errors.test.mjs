import test from "node:test";
import assert from "node:assert/strict";

// Mirrors the transport layer of mfd-cli.mjs (the CLI executes side effects on
// import, so the pure helpers are replicated here, as in token-resolver.test.mjs).

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

test("unwrapNetworkError reads the real errno from the cause chain", () => {
  const err = new TypeError("fetch failed");
  err.cause = Object.assign(new Error("getaddrinfo ENOTFOUND lsa.lenovo.com"), {
    code: "ENOTFOUND",
    syscall: "getaddrinfo",
    hostname: "lsa.lenovo.com"
  });

  const detail = unwrapNetworkError(err);
  assert.equal(detail.code, "ENOTFOUND");
  assert.equal(detail.syscall, "getaddrinfo");
  assert.equal(detail.hostname, "lsa.lenovo.com");
  assert.equal(detail.message, "getaddrinfo ENOTFOUND lsa.lenovo.com");
  assert.equal(detail.transient, false);
});

test("unwrapNetworkError walks nested causes and stops on cycles", () => {
  const deep = Object.assign(new Error("connect ETIMEDOUT"), { code: "ETIMEDOUT" });
  const mid = Object.assign(new Error("fetch failed"), { cause: deep });
  mid.cause.cause = mid;

  const detail = unwrapNetworkError(mid);
  assert.equal(detail.code, "ETIMEDOUT");
  assert.equal(detail.transient, true);
});

test("unwrapNetworkError degrades safely on a bare error", () => {
  const detail = unwrapNetworkError(new Error("plain failure"));
  assert.equal(detail.code, "");
  assert.equal(detail.transient, false);
  assert.equal(detail.message, "plain failure");
});

test("transient classification covers undici and socket codes", () => {
  for (const code of ["ECONNRESET", "UND_ERR_CONNECT_TIMEOUT", "UND_ERR_SOCKET", "EHOSTUNREACH"]) {
    const err = Object.assign(new Error("fetch failed"), { code });
    assert.equal(unwrapNetworkError(err).transient, true, `${code} should be transient`);
  }
  for (const code of ["ENOTFOUND", "CERT_HAS_EXPIRED", "ERR_INVALID_URL"]) {
    const err = Object.assign(new Error("fetch failed"), { code });
    assert.equal(unwrapNetworkError(err).transient, false, `${code} should not be retried`);
  }
});

test("retry loop aborts non-transient faults on the first attempt", async () => {
  let attempts = 0;
  const fetchLike = async () => {
    attempts += 1;
    const err = new TypeError("fetch failed");
    err.cause = Object.assign(new Error("getaddrinfo ENOTFOUND"), { code: "ENOTFOUND" });
    throw err;
  };

  const run = async () => {
    const max = 3;
    for (let i = 1; i <= max; i++) {
      try {
        return await fetchLike();
      } catch (err) {
        const detail = unwrapNetworkError(err);
        if (!detail.transient || i === max) throw err;
      }
    }
  };

  await assert.rejects(run, /fetch failed/);
  assert.equal(attempts, 1);
});

test("retry loop exhausts attempts on transient faults", async () => {
  let attempts = 0;
  const fetchLike = async () => {
    attempts += 1;
    const err = new TypeError("fetch failed");
    err.cause = Object.assign(new Error("socket hang up"), { code: "ECONNRESET" });
    throw err;
  };

  const run = async () => {
    const max = 3;
    for (let i = 1; i <= max; i++) {
      try {
        return await fetchLike();
      } catch (err) {
        const detail = unwrapNetworkError(err);
        if (!detail.transient || i === max) throw err;
      }
    }
  };

  await assert.rejects(run, /fetch failed/);
  assert.equal(attempts, 3);
});
