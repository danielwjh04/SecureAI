import { describe, expect, it } from 'vitest'
import { commandTouchesSensitivePath, commandWritesToConfigPath, hasShellMetacharacters } from './commandRisk'

const MARKERS = new Set(['.ssh/id_rsa', '.env', 'secret', 'credentials'])

const BOUNDARY_MARKERS = new Set(['/root/', '.env', '.ssh/id_rsa', 'secret'])

describe('commandTouchesSensitivePath', () => {
  it('returns true for a multi-segment marker in a real secret path', () => {
    expect(commandTouchesSensitivePath('cat ~/.ssh/id_rsa', MARKERS)).toBe(true)
  })

  it('returns true for a dotfile marker bounded by a space and end of string', () => {
    expect(commandTouchesSensitivePath('cat .env', MARKERS)).toBe(true)
  })

  it('returns true when marker is bounded by a space and a dot', () => {
    expect(commandTouchesSensitivePath('cat secret.txt', MARKERS)).toBe(true)
  })

  it('returns false for a marker appearing inside a longer alphanumeric word (no false positive)', () => {
    expect(commandTouchesSensitivePath('cat secretariat.md', MARKERS)).toBe(false)
  })

  it('returns true for a Windows-style path after backslash normalization', () => {
    expect(commandTouchesSensitivePath('type C:\\Users\\me\\.ssh\\id_rsa', MARKERS)).toBe(true)
  })

  it('returns false for an empty marker set', () => {
    expect(commandTouchesSensitivePath('cat ~/.ssh/id_rsa', new Set())).toBe(false)
  })

  it('returns false for an empty command', () => {
    expect(commandTouchesSensitivePath('', MARKERS)).toBe(false)
  })

  it('returns true when marker appears as the whole argument (boundary at both ends)', () => {
    expect(commandTouchesSensitivePath('ls credentials', MARKERS)).toBe(true)
  })

  it('returns false for a benign command with no marker', () => {
    expect(commandTouchesSensitivePath('cat README.md', MARKERS)).toBe(false)
  })

  it('returns true for an uppercase path that normalizes to match', () => {
    expect(commandTouchesSensitivePath('cat /home/user/.ENV', MARKERS)).toBe(true)
  })
})

describe('containsBoundedMarker boundary-char shortcuts', () => {
  it('matches /root/ in "cat /root/wallet.dat" (marker ends with boundary char /)', () => {
    expect(commandTouchesSensitivePath('cat /root/wallet.dat', BOUNDARY_MARKERS)).toBe(true)
  })

  it('matches .env in "cat myapp.env" (marker starts with boundary char .)', () => {
    expect(commandTouchesSensitivePath('cat myapp.env', BOUNDARY_MARKERS)).toBe(true)
  })

  it('matches .ssh/id_rsa in "cat ~/.ssh/id_rsa" (marker starts with .)', () => {
    expect(commandTouchesSensitivePath('cat ~/.ssh/id_rsa', BOUNDARY_MARKERS)).toBe(true)
  })

  it('does not match "secret" inside "secretariat.md" (alphanumeric on both ends)', () => {
    expect(commandTouchesSensitivePath('cat secretariat.md', BOUNDARY_MARKERS)).toBe(false)
  })
})

describe('hasShellMetacharacters', () => {
  it('detects command substitution, chaining, and redirection', () => {
    for (const cmd of ['echo $(chmod 777 /etc)', 'echo x&&rm -rf /', 'echo `id`', 'echo x > f', 'a || b', 'a | b']) {
      expect(hasShellMetacharacters(cmd)).toBe(true)
    }
  })
  it('treats a single simple command as metacharacter-free', () => {
    expect(hasShellMetacharacters('cat README.md')).toBe(false)
  })
})

describe('commandWritesToConfigPath', () => {
  const markers = new Set(['.claude', 'package.json'])

  it('flags a redirect into a config path', () => {
    expect(commandWritesToConfigPath('echo x >> .claude/settings.json', markers)).toBe(true)
  })

  it('does not flag a plain read of a config path', () => {
    expect(commandWritesToConfigPath('cat package.json', markers)).toBe(false)
  })

  it('does not flag a partial marker match (boundary-aware)', () => {
    expect(commandWritesToConfigPath('echo x >> mypackage.json', new Set(['package.json']))).toBe(false)
  })

  it('flags tee writing to a config path', () => {
    expect(commandWritesToConfigPath('echo y | tee .claude/settings.json', markers)).toBe(true)
  })

  it('does not flag a write to a non-config path', () => {
    expect(commandWritesToConfigPath('echo y >> output.log', markers)).toBe(false)
  })
})
