import test from "node:test";
import assert from "node:assert/strict";

function isValidSessionToken(str) {
  if (typeof str !== "string") return false;
  const trimmed = str.trim();
  if (isJwt(trimmed)) return true;
  if (/^[a-fA-F0-9]{32}$/.test(trimmed)) return true;
  return false;
}

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

function extractDirectToken(rawInput) {
  if (!rawInput || typeof rawInput !== "string") return null;
  let input = rawInput.trim().replace(/^["']|["']$/g, "");

  const mAuth = input.match(/(?:Authorization|auth|token)=([^&\s"<>]+)/i);
  if (mAuth?.[1]) {
    let token = decodeURIComponent(mAuth[1]).trim();
    if (token.startsWith("Bearer ")) token = token.slice(7).trim();
    if (isValidSessionToken(token)) return token;
  }

  if (input.startsWith("Bearer ")) {
    const token = input.slice(7).trim();
    if (isValidSessionToken(token)) return token;
  }

  if (isValidSessionToken(input)) {
    return input;
  }

  return null;
}

test("isValidSessionToken validation", () => {
  const validJwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature123";
  assert.equal(isValidSessionToken(validJwt), true);

  const validLmsaHash = "35f6af963deb4237b8a8669d880e6e83";
  assert.equal(isValidSessionToken(validLmsaHash), true);

  // 64-char hex authorization codes should NOT be accepted as direct tokens
  assert.equal(isValidSessionToken("4428add522bb33cc44dd55ee66ff77aa88bb99cc00dd11ee22ff33aa44bb55cc"), false);
  assert.equal(isValidSessionToken("https://lsa.lenovo.com/Tips/lenovoIdSuccess.html?code=12345"), false);
  assert.equal(isValidSessionToken(""), false);
  assert.equal(isValidSessionToken(null), false);
});

test("extractDirectToken handles softwareFix URI with JWT", () => {
  const jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature123";
  const softwareFixUri = `softwareFix://authcallback?Authorization=${jwt}`;
  assert.equal(extractDirectToken(softwareFixUri), jwt);
});

test("extractDirectToken handles Firefox softwarefix://callback URI with 32-hex token", () => {
  const token = "35f6af963deb4237b8a8669d880e6e83";
  const firefoxUri = `softwarefix://callback?fullName=user@example.com&Authorization=${token}`;
  assert.equal(extractDirectToken(firefoxUri), token);
});

test("extractDirectToken handles Bearer string", () => {
  const token = "35f6af963deb4237b8a8669d880e6e83";
  assert.equal(extractDirectToken(`Bearer ${token}`), token);
});

test("extractDirectToken handles direct 32-hex token", () => {
  const token = "35f6af963deb4237b8a8669d880e6e83";
  assert.equal(extractDirectToken(token), token);
});

test("extractDirectToken rejects invalid 64-hex codes", () => {
  assert.equal(extractDirectToken("a4d41234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"), null);
});
