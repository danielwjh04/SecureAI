// @vitest-environment node
import { describe, expect, it } from 'vitest'
import {
  dedupeAndCap,
  parseThreatfoxCsv,
  parseUrlhausHostfile,
  parseUrlhausUrlList,
  type FeedIndicator,
} from './feedParse'

describe('parseUrlhausHostfile', () => {
  it('skips comments/blanks and takes the host (last token), lowercased', () => {
    const body = '# title\n#\n127.0.0.1\tEvil.com\n\n0.0.0.0 Bad.TEST\nplain.example\n'
    expect(parseUrlhausHostfile(body)).toEqual([
      { kind: 'host', value: 'evil.com', source: 'urlhaus' },
      { kind: 'host', value: 'bad.test', source: 'urlhaus' },
      { kind: 'host', value: 'plain.example', source: 'urlhaus' },
    ])
  })
})

describe('parseUrlhausUrlList', () => {
  it('skips comments and normalizes URLs, dropping unparseable lines', () => {
    const body = '# title\nhttp://Evil.com/Path\nnot a url\nhttps://evil.com/Path\n'
    expect(parseUrlhausUrlList(body)).toEqual([
      { kind: 'url', value: 'evil.com/Path', source: 'urlhaus' },
      // the same resource over https normalizes identically (de-dup is a later step)
      { kind: 'url', value: 'evil.com/Path', source: 'urlhaus' },
    ])
  })
})

describe('parseThreatfoxCsv', () => {
  it('keeps domain/url IOCs (handling quoted commas), skips ip:port and hashes', () => {
    const body = [
      '# first_seen,ioc_id,ioc_value,ioc_type,threat_type,malware',
      '"2024-01-01 00:00:00","1","Bad.Domain.com","domain","botnet_cc","Malware"',
      '"2024-01-01 00:00:00","2","http://evil.test/a?x=1,2","url","payload_delivery","Malware"',
      '"2024-01-01 00:00:00","3","1.2.3.4:8080","ip:port","botnet_cc","Malware"',
      '"2024-01-01 00:00:00","4","d41d8cd98f00b204e9800998ecf8427e","md5_hash","payload","Malware"',
      '',
    ].join('\n')
    expect(parseThreatfoxCsv(body)).toEqual([
      { kind: 'host', value: 'bad.domain.com', source: 'threatfox' },
      { kind: 'url', value: 'evil.test/a?x=1,2', source: 'threatfox' },
    ])
  })
})

describe('dedupeAndCap', () => {
  const make = (n: number): FeedIndicator[] =>
    Array.from({ length: n }, (_, i) => ({ kind: 'host', value: `h${i}.test`, source: 'urlhaus' }))

  it('drops exact (kind,value) duplicates, keeping the first', () => {
    const input: FeedIndicator[] = [
      { kind: 'host', value: 'evil.com', source: 'urlhaus' },
      { kind: 'host', value: 'evil.com', source: 'threatfox' },
      { kind: 'url', value: 'evil.com/', source: 'urlhaus' },
    ]
    const out = dedupeAndCap(input, 100)
    expect(out.indicators).toEqual([
      { kind: 'host', value: 'evil.com', source: 'urlhaus' },
      { kind: 'url', value: 'evil.com/', source: 'urlhaus' },
    ])
    expect(out.dropped).toBe(0)
  })

  it('caps to maxRows and reports the dropped count (never silent truncation)', () => {
    const out = dedupeAndCap(make(10), 4)
    expect(out.indicators).toHaveLength(4)
    expect(out.dropped).toBe(6)
  })
})
