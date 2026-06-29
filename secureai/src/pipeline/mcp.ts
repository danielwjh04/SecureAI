import type { McpScanInput, RuleFinding, Verdict } from '../schemas/contract'

const RULE_MCP_EXEC_TOOL = 'mcp.exec_capable_tool'
const RULE_MCP_SECRET_ACCESS = 'mcp.secret_access'
const RULE_MCP_RAW_IP_ENDPOINT = 'mcp.raw_ip_endpoint'
const RULE_MCP_PRIVATE_ENDPOINT = 'mcp.private_endpoint'
const RULE_MCP_OVERBROAD_PERMISSION = 'mcp.overbroad_permission'
const RULE_MCP_CONFIG_MUTATION = 'mcp.config_mutation'

const EXEC_TOKENS = ['shell', 'bash', 'exec', 'command', 'process', 'terminal', 'powershell']
const SECRET_TOKENS = ['secret', 'token', 'password', 'credential', 'private_key', 'api_key', 'ssh']
const OVERBROAD_TOKENS = ['*', 'all', 'admin', 'root', 'filesystem:*', 'files:*', 'network:*']
const CONFIG_MUTATION_TOKENS = ['shell config', 'bashrc', 'zshrc', 'profile', 'agent config', 'claude config', 'codex config']

interface MappedEndpoint {
  readonly raw: string
  readonly parsed: URL | null
}

function lowercase(value: string): string {
  return value.toLowerCase()
}

function asText(value: unknown): string {
  if (typeof value === 'string') return value
  try {
    return JSON.stringify(value)
  } catch {
    return String(value)
  }
}

function normalizeEnvKeys(env: McpScanInput['env']): string[] {
  if (env === undefined) return []
  if (Array.isArray(env)) return env
  return Object.keys(env)
}

function endpointsOf(input: McpScanInput): MappedEndpoint[] {
  const raw = [input.endpoint, ...(input.endpoints ?? [])].filter(
    (value): value is string => value !== undefined,
  )
  return raw.map((endpoint) => {
    try {
      return { raw: endpoint, parsed: new URL(endpoint) }
    } catch {
      return { raw: endpoint, parsed: null }
    }
  })
}

function isRawIp(host: string): boolean {
  if (host.includes(':')) return true
  const parts = host.split('.')
  if (parts.length !== 4) return false
  return parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255)
}

function ipv4ToNumber(host: string): number | null {
  const parts = host.split('.')
  if (parts.length !== 4) return null
  let value = 0
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null
    const octet = Number(part)
    if (octet > 255) return null
    value = value * 256 + octet
  }
  return value
}

function isPrivateIpv4(host: string): boolean {
  const value = ipv4ToNumber(host)
  if (value === null) return false
  const ranges: readonly [number, number][] = [
    [0x0a000000, 0x0affffff],
    [0xac100000, 0xac1fffff],
    [0xc0a80000, 0xc0a8ffff],
    [0x7f000000, 0x7fffffff],
    [0xa9fe0000, 0xa9feffff],
  ]
  return ranges.some(([start, end]) => value >= start && value <= end)
}

function containsAny(text: string, tokens: readonly string[]): boolean {
  const normalized = lowercase(text)
  return tokens.some((token) => normalized.includes(token))
}

function record(
  findings: RuleFinding[],
  ruleId: string,
  severity: Verdict,
  detail: string,
): void {
  findings.push({ ruleId, severity, detail })
}

/**
 * Serialize an MCP config/setup object into scanner text so existing URL and
 * download-and-run parsing can inspect the same observable material.
 *
 * Time complexity: O(n) in the serialized input size. Space complexity: O(n).
 */
export function buildMcpScanText(input: McpScanInput): string {
  const lines: string[] = ['# MCP scan']
  if (input.name !== undefined) lines.push(`name: ${input.name}`)
  if (input.transport !== undefined) lines.push(`transport: ${input.transport}`)
  if (input.command !== undefined) lines.push(`command: ${input.command}`)
  if (input.args !== undefined) lines.push(`args: ${input.args.join(' ')}`)
  if (input.endpoint !== undefined) lines.push(`endpoint: ${input.endpoint}`)
  if (input.endpoints !== undefined) lines.push(`endpoints: ${input.endpoints.join(' ')}`)
  if (input.permissions !== undefined) lines.push(`permissions: ${input.permissions.join(' ')}`)
  const envKeys = normalizeEnvKeys(input.env)
  if (envKeys.length > 0) lines.push(`env: ${envKeys.join(' ')}`)
  for (const tool of input.tools ?? []) {
    lines.push(`tool: ${tool.name}`)
    if (tool.description !== undefined) lines.push(`description: ${tool.description}`)
    if (tool.permissions !== undefined) lines.push(`tool permissions: ${tool.permissions.join(' ')}`)
    if (tool.inputSchema !== undefined) lines.push(`tool input schema: ${asText(tool.inputSchema)}`)
  }
  if (input.setup !== undefined) lines.push(input.setup)
  if (input.config !== undefined) lines.push(`config: ${asText(input.config)}`)
  return lines.join('\n')
}

/**
 * Evaluate deterministic MCP-specific rules before reputation and AI stages.
 *
 * Time complexity: O(t + p + e) in tools, permissions, and endpoints. Space
 * complexity: O(f) in findings.
 */
export function evaluateMcpRules(input: McpScanInput): RuleFinding[] {
  const findings: RuleFinding[] = []
  const topPermissions = input.permissions ?? []
  const setup = input.setup ?? ''

  for (const tool of input.tools ?? []) {
    const toolText = `${tool.name} ${tool.description ?? ''} ${(tool.permissions ?? []).join(' ')}`
    if (containsAny(toolText, EXEC_TOKENS)) {
      record(findings, RULE_MCP_EXEC_TOOL, 'BLOCK', `MCP tool ${tool.name} can execute commands or processes`)
    }
    if (containsAny(toolText, SECRET_TOKENS)) {
      record(findings, RULE_MCP_SECRET_ACCESS, 'BLOCK', `MCP tool ${tool.name} can access secrets or credentials`)
    }
    if (containsAny(toolText, CONFIG_MUTATION_TOKENS)) {
      record(findings, RULE_MCP_CONFIG_MUTATION, 'HUMAN_APPROVAL_REQUIRED', `MCP tool ${tool.name} can modify shell or agent config`)
    }
  }

  for (const permission of topPermissions) {
    if (OVERBROAD_TOKENS.some((token) => lowercase(permission) === token || lowercase(permission).includes(token))) {
      record(findings, RULE_MCP_OVERBROAD_PERMISSION, 'HUMAN_APPROVAL_REQUIRED', `MCP permission is broad: ${permission}`)
    }
    if (containsAny(permission, SECRET_TOKENS)) {
      record(findings, RULE_MCP_SECRET_ACCESS, 'BLOCK', `MCP permission can access secrets: ${permission}`)
    }
  }

  for (const envKey of normalizeEnvKeys(input.env)) {
    if (containsAny(envKey, SECRET_TOKENS)) {
      record(findings, RULE_MCP_SECRET_ACCESS, 'BLOCK', `MCP environment access includes secret-like key: ${envKey}`)
    }
  }

  for (const endpoint of endpointsOf(input)) {
    const host = endpoint.parsed?.hostname.toLowerCase()
    if (host === undefined) continue
    if (isRawIp(host)) {
      record(findings, RULE_MCP_RAW_IP_ENDPOINT, 'HUMAN_APPROVAL_REQUIRED', `MCP endpoint uses a raw IP host: ${endpoint.raw}`)
    }
    if (isPrivateIpv4(host) || host === 'localhost') {
      record(findings, RULE_MCP_PRIVATE_ENDPOINT, 'BLOCK', `MCP endpoint targets a private or local host: ${endpoint.raw}`)
    }
  }

  if (containsAny(setup, CONFIG_MUTATION_TOKENS)) {
    record(findings, RULE_MCP_CONFIG_MUTATION, 'HUMAN_APPROVAL_REQUIRED', 'MCP setup can modify shell or agent config')
  }

  return findings
}
