// @vitest-environment node
import { describe, expect, it } from 'vitest'
import { normalizeIndicatorUrl } from './normalizeUrl'

// normalizeIndicatorUrl produces the canonical match key shared by feed ingestion
// and scan-time lookup: it MUST be byte-identical on both sides (like the proof's
// canonical bytes), so these cases pin the exact normalization contract.

describe('normalizeIndicatorUrl', () => {
  it('lowercases the host, keeps the path case, the query, and drops the fragment', () => {
    expect(normalizeIndicatorUrl('http://Evil.COM/Path/x?q=1#frag')).toBe('evil.com/Path/x?q=1')
  })

  it('is scheme-insensitive: http and https normalize identically', () => {
    expect(normalizeIndicatorUrl('http://evil.com/a?b=1')).toBe(
      normalizeIndicatorUrl('https://evil.com/a?b=1'),
    )
  })

  it('represents a root URL with the "/" pathname (host value never collides with a url value)', () => {
    expect(normalizeIndicatorUrl('http://evil.com')).toBe('evil.com/')
    expect(normalizeIndicatorUrl('https://evil.com/')).toBe('evil.com/')
  })

  it('keeps the path exact, a trailing slash is significant', () => {
    expect(normalizeIndicatorUrl('http://evil.com/a')).toBe('evil.com/a')
    expect(normalizeIndicatorUrl('http://evil.com/a/')).toBe('evil.com/a/')
  })

  it('strips a default port and userinfo, keeps a non-default port', () => {
    expect(normalizeIndicatorUrl('https://evil.com:443/x')).toBe('evil.com/x')
    expect(normalizeIndicatorUrl('http://evil.com:80/x')).toBe('evil.com/x')
    expect(normalizeIndicatorUrl('http://user:pass@evil.com/x')).toBe('evil.com/x')
    expect(normalizeIndicatorUrl('http://evil.com:8080/x')).toBe('evil.com:8080/x')
  })

  it('returns null for an unparseable URL or one with no host', () => {
    expect(normalizeIndicatorUrl('not a url')).toBeNull()
    expect(normalizeIndicatorUrl('mailto:a@b.com')).toBeNull()
    expect(normalizeIndicatorUrl('')).toBeNull()
  })
})
