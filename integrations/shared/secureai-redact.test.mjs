import assert from 'node:assert/strict'
import { test } from 'node:test'
import { redactString, redactSecrets, computeContentHash, applyPrivacyMode, REDACTED } from './secureai-redact.mjs'

test('redacts a hyphenated Slack bot token', () => {
  assert.doesNotMatch(redactString('use xoxb-12345678901-abcdefABCDEF as token'), /xoxb-12345678901-abcdefABCDEF/)
})
test('redacts an AWS access key id with no separator', () => {
  assert.doesNotMatch(redactString('AKIAIOSFODNN7EXAMPLE in config'), /AKIAIOSFODNN7EXAMPLE/)
})
test('redacts a PEM private key block', () => {
  const pem = '-----BEGIN RSA PRIVATE KEY-----\nMIIBVAIBADANBgkq\n-----END RSA PRIVATE KEY-----'
  const out = redactString(pem)
  assert.doesNotMatch(out, /MIIBVAIBADANBgkq/)
})
test('redacts the password in a connection string but keeps scheme and host shape', () => {
  const out = redactString('DATABASE_URL=postgres://user:p4ssw0rd@db.example.com:5432/app')
  assert.doesNotMatch(out, /p4ssw0rd/)
})
test('redacts a JWT', () => {
  assert.doesNotMatch(redactString('auth eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc-_123'), /eyJzdWIiOiIxIn0/)
})
test('does not over-redact ordinary prose', () => {
  assert.equal(redactString('the quick brown fox jumps over the lazy dog'), 'the quick brown fox jumps over the lazy dog')
})
test('redactSecrets redacts an object value whose key looks secret', () => {
  assert.equal(redactSecrets({ api_key: 'live123', note: 'ok' }).api_key, REDACTED)
})
test('computeContentHash is deterministic and key-order independent', () => {
  const a = computeContentHash({ tool_name: 'Bash', tool_input: { command: 'ls', cwd: '/p' } })
  const b = computeContentHash({ tool_name: 'Bash', tool_input: { cwd: '/p', command: 'ls' } })
  assert.equal(a, b)
  assert.match(a, /^[0-9a-f]{64}$/)
})
test('maximum mode drops content but keeps tool_name and content_hash', () => {
  const out = applyPrivacyMode({ tool_name: 'Bash', tool_input: { command: 'ls' }, content_hash: 'h', session_id: 's', cwd: '/p' }, 'maximum')
  assert.equal(out.tool_input, undefined)
  assert.equal(out.session_id, undefined)
  assert.equal(out.cwd, undefined)
  assert.equal(out.tool_name, 'Bash')
  assert.equal(out.content_hash, 'h')
})
test('balanced mode keeps redacted content and hash', () => {
  const out = applyPrivacyMode({ tool_name: 'Bash', tool_input: { command: 'GITHUB_TOKEN=ghp_abcdefghijklmno ls' }, content_hash: 'h' }, 'balanced')
  assert.doesNotMatch(JSON.stringify(out), /ghp_abcdefghijklmno/)
  assert.equal(out.content_hash, 'h')
})

// Fix 1: bare keyword assignments
test('redacts bare PASSWORD= assignment', () => {
  assert.doesNotMatch(redactString('PASSWORD=secret123'), /secret123/)
})
test('redacts bare TOKEN= assignment', () => {
  assert.doesNotMatch(redactString('TOKEN=abc123def'), /abc123def/)
})
test('redacts bare API_KEY= assignment', () => {
  assert.doesNotMatch(redactString('API_KEY=k9k9k9k9'), /k9k9k9k9/)
})
test('does not over-redact count=5', () => {
  assert.equal(redactString('count=5'), 'count=5')
})

// Fix 2: connection strings with empty username
test('redacts password in redis connection string with no username', () => {
  assert.doesNotMatch(redactString('redis://:p4ssw0rd@cache:6379'), /p4ssw0rd/)
})
test('redacts password in postgres connection string but keeps scheme+user and host', () => {
  const out = redactString('postgres://user:secretpw@db/app')
  assert.doesNotMatch(out, /secretpw/)
  assert.match(out, /postgres:\/\/user:/)
  assert.match(out, /@db\/app/)
})

// Fix 3: alg:none JWT with empty signature segment
test('redacts alg:none JWT with empty third segment', () => {
  assert.doesNotMatch(redactString('token eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.'), /eyJzdWIiOiIxIn0/)
})

// Fix 4: HuggingFace hf_ prefix token
test('redacts HuggingFace hf_ prefixed token', () => {
  assert.doesNotMatch(redactString('use hf_abcdefghijklmnop here'), /hf_abcdefghijklmnop/)
})
