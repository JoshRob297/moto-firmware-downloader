import test from "node:test";
import assert from "node:assert/strict";

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
    if (isJwt(token)) return token;
  }

  if (input.startsWith("Bearer ")) {
    const token = input.slice(7).trim();
    if (isJwt(token)) return token;
  }

  if (isJwt(input)) {
    return input;
  }

  return null;
}

test("isJwt validation", () => {
  const validJwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature123";
  assert.equal(isJwt(validJwt), true);
  assert.equal(isJwt("4428add522bb33cc44dd55ee66ff77aa88bb99cc00dd11ee22ff33aa44bb55cc"), false);
  assert.equal(isJwt("https://lsa.lenovo.com/Tips/lenovoIdSuccess.html?code=12345"), false);
  assert.equal(isJwt(""), false);
  assert.equal(isJwt(null), false);
});

test("extractDirectToken handles softwareFix URI", () => {
  const jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature123";
  const softwareFixUri = `softwareFix://authcallback?Authorization=${jwt}`;
  assert.equal(extractDirectToken(softwareFixUri), jwt);
});

test("extractDirectToken handles Bearer string", () => {
  const jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature123";
  assert.equal(extractDirectToken(`Bearer ${jwt}`), jwt);
});

test("extractDirectToken rejects invalid non-JWT codes", () => {
  assert.equal(extractDirectToken("a4d41234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"), null);
});
