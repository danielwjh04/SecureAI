// @vitest-environment node
import { describe, expect, it } from 'vitest'
import { RedirectResolutionError } from '../errors'
import {
  assertSafeUrl,
  isPrivateOrLoopbackHost,
  isRawIpLiteral,
  type SsrfConfig,
} from './ssrf'

// https-only, matching the documented SCANNER_ALLOWED_SCHEMES default.
const CONFIG: SsrfConfig = { allowedSchemes: new Set(['https']) }

/** Convenience: parse and assert in one step so tests read as URL strings. */
function assert(urlString: string): void {
  assertSafeUrl(new URL(urlString), CONFIG)
}

describe('assertSafeUrl, scheme', () => {
  it('accepts a normal https URL', () => {
    expect(() => assert('https://example.com/path')).not.toThrow()
  })

  it('rejects http (not in the allowed scheme set)', () => {
    expect(() => assert('http://example.com/path')).toThrow(
      RedirectResolutionError,
    )
  })

  it('rejects non-web schemes (ftp, file, data, gopher)', () => {
    expect(() => assert('ftp://example.com/x')).toThrow(RedirectResolutionError)
    expect(() => assert('file:///etc/passwd')).toThrow(RedirectResolutionError)
    expect(() => assert('gopher://example.com/')).toThrow(
      RedirectResolutionError,
    )
  })
})

describe('assertSafeUrl, raw IP literals', () => {
  it('rejects a raw IPv4 literal host', () => {
    expect(() => assert('https://93.184.216.34/')).toThrow(
      RedirectResolutionError,
    )
  })

  it('rejects a raw IPv6 literal host', () => {
    expect(() => assert('https://[2001:db8::1]/')).toThrow(
      RedirectResolutionError,
    )
  })
})

describe('assertSafeUrl, private / loopback / link-local', () => {
  it('rejects RFC1918 10.0.0.0/8', () => {
    expect(() => assert('https://10.1.2.3/')).toThrow(RedirectResolutionError)
  })

  it('rejects RFC1918 172.16.0.0/12', () => {
    expect(() => assert('https://172.16.5.5/')).toThrow(RedirectResolutionError)
    expect(() => assert('https://172.31.255.255/')).toThrow(
      RedirectResolutionError,
    )
  })

  it('rejects RFC1918 192.168.0.0/16', () => {
    expect(() => assert('https://192.168.1.1/')).toThrow(RedirectResolutionError)
  })

  it('rejects IPv4 loopback 127.0.0.0/8', () => {
    expect(() => assert('https://127.0.0.1/')).toThrow(RedirectResolutionError)
  })

  it('rejects IPv4 link-local 169.254.0.0/16', () => {
    expect(() => assert('https://169.254.169.254/')).toThrow(
      RedirectResolutionError,
    )
  })

  it('rejects IPv6 loopback ::1', () => {
    expect(() => assert('https://[::1]/')).toThrow(RedirectResolutionError)
  })

  it('rejects IPv6 link-local fe80::/10', () => {
    expect(() => assert('https://[fe80::1]/')).toThrow(RedirectResolutionError)
  })
})

describe('assertSafeUrl, internal hostnames', () => {
  it('rejects localhost', () => {
    expect(() => assert('https://localhost/')).toThrow(RedirectResolutionError)
  })

  it('rejects *.internal', () => {
    expect(() => assert('https://api.internal/')).toThrow(
      RedirectResolutionError,
    )
  })

  it('rejects *.local', () => {
    expect(() => assert('https://printer.local/')).toThrow(
      RedirectResolutionError,
    )
  })
})

describe('assertSafeUrl, accepts legitimate public https', () => {
  it('accepts a normal public hostname with a port and path', () => {
    expect(() => assert('https://example.com:443/a/b?c=d')).not.toThrow()
  })

  it('accepts a subdomain that merely contains the word internal', () => {
    // ".internal" is a suffix check; "internal-docs.example.com" must pass.
    expect(() => assert('https://internal-docs.example.com/')).not.toThrow()
  })
})

describe('isRawIpLiteral', () => {
  it('recognizes IPv4 dotted-quads', () => {
    expect(isRawIpLiteral('8.8.8.8')).toBe(true)
    expect(isRawIpLiteral('192.168.0.1')).toBe(true)
  })

  it('recognizes IPv6 literals by their colon', () => {
    expect(isRawIpLiteral('::1')).toBe(true)
    expect(isRawIpLiteral('fe80::1')).toBe(true)
  })

  it('rejects malformed dotted-quads with out-of-range octets', () => {
    expect(isRawIpLiteral('256.0.0.1')).toBe(false)
    expect(isRawIpLiteral('1.2.3')).toBe(false)
  })

  it('returns false for DNS names', () => {
    expect(isRawIpLiteral('example.com')).toBe(false)
    expect(isRawIpLiteral('a.b.c.d.example')).toBe(false)
  })
})

describe('isPrivateOrLoopbackHost', () => {
  it('flags private IPv4 ranges', () => {
    expect(isPrivateOrLoopbackHost('10.0.0.1')).toBe(true)
    expect(isPrivateOrLoopbackHost('172.20.0.1')).toBe(true)
    expect(isPrivateOrLoopbackHost('192.168.0.1')).toBe(true)
    expect(isPrivateOrLoopbackHost('127.0.0.1')).toBe(true)
    expect(isPrivateOrLoopbackHost('169.254.0.1')).toBe(true)
  })

  it('does NOT flag public IPv4 just outside the private ranges', () => {
    // 172.15.x and 172.32.x are public (the private band is only 172.16-172.31).
    expect(isPrivateOrLoopbackHost('172.15.0.1')).toBe(false)
    expect(isPrivateOrLoopbackHost('172.32.0.1')).toBe(false)
    expect(isPrivateOrLoopbackHost('8.8.8.8')).toBe(false)
  })

  it('flags internal names and IPv6 loopback/link-local', () => {
    expect(isPrivateOrLoopbackHost('localhost')).toBe(true)
    expect(isPrivateOrLoopbackHost('svc.internal')).toBe(true)
    expect(isPrivateOrLoopbackHost('host.local')).toBe(true)
    expect(isPrivateOrLoopbackHost('::1')).toBe(true)
    expect(isPrivateOrLoopbackHost('fe80::abcd')).toBe(true)
  })

  it('does NOT flag ordinary public hostnames', () => {
    expect(isPrivateOrLoopbackHost('example.com')).toBe(false)
    expect(isPrivateOrLoopbackHost('cdn.example.org')).toBe(false)
  })
})
