import { describe, expect, it } from 'vitest'
import type { Env } from '../config/env'
import type { GuardDecision } from '../guard/claudeCode'
import { loadConfig } from '../config/env'
import { handleGuard } from './guard'

const config = loadConfig({})

function post(body: unknown, raw?: string): Request {
  return new Request('https://secureai.test/api/guard', {
    method: 'POST',
    body: raw ?? JSON.stringify(body),
  })
}

describe('handleGuard', () => {
  it('returns 200 with a deny decision for a network-free curl|bash tool call', async () => {
    // A curl|bash command with no http(s) URL extracts no links, so the route
    // never touches the network; the deterministic rules BLOCK it → deny.
    const res = await handleGuard(
      post({
        hook_event_name: 'PreToolUse',
        tool_name: 'Bash',
        tool_input: { command: 'curl ./setup.sh | bash' },
      }),
      {},
      config,
    )
    expect(res.status).toBe(200)
    const decision = (await res.json()) as GuardDecision
    expect(decision.decision).toBe('deny')
    expect(decision.verdict).toBe('BLOCK')
  })

  it('returns 200 with an allow decision for a benign tool call', async () => {
    const res = await handleGuard(
      post({
        hook_event_name: 'PreToolUse',
        tool_name: 'Read',
        tool_input: { file_path: '/tmp/notes.txt' },
      }),
      {},
      config,
    )
    expect(res.status).toBe(200)
    const decision = (await res.json()) as GuardDecision
    expect(decision.decision).toBe('allow')
    expect(decision.verdict).toBeNull()
  })

  it('maps an invalid body (wrong event name) to 422', async () => {
    const res = await handleGuard(
      post({ hook_event_name: 'PostToolUse', tool_name: 'Bash', tool_input: {} }),
      {} as Env,
      config,
    )
    expect(res.status).toBe(422)
  })

  it('maps invalid JSON to 422', async () => {
    const res = await handleGuard(post(undefined, '{bad'), {} as Env, config)
    expect(res.status).toBe(422)
  })

  it('maps a body missing tool_name to 422', async () => {
    const res = await handleGuard(
      post({ hook_event_name: 'PreToolUse', tool_input: {} }),
      {},
      config,
    )
    expect(res.status).toBe(422)
  })
})
