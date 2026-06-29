const SECOND_MS = 1000
const MINUTE_MS = 60 * SECOND_MS

/** Runtime-tunable extension defaults kept in one module instead of scattered literals. */
export const EXTENSION_CONFIG = {
  apiBase: 'https://secureai.software',
  scanPath: '/api/scan',
  requestTimeoutMs: 8000,
  verdictCacheTtlMs: 5 * MINUTE_MS,
  dnrRuleBudget: 5000,
  maxContentChars: 20000,
  storageKeys: {
    settings: 'secureai.settings',
    verdictCache: 'secureai.verdictCache',
    dnrMetadata: 'secureai.dnrMetadata',
    stats: 'secureai.stats',
  },
  pairingParams: ['secureai_key', 'secureaiPairKey', 'key'],
  dnrResourceTypes: [
    'main_frame',
    'sub_frame',
    'stylesheet',
    'script',
    'image',
    'font',
    'object',
    'xmlhttprequest',
    'ping',
    'csp_report',
    'media',
    'websocket',
    'other',
  ],
  supportedHosts: {
    github: ['github.com', 'raw.githubusercontent.com'],
    ai: ['chatgpt.com', 'chat.openai.com', 'claude.ai', 'www.perplexity.ai'],
  },
  destinationRiskCategories: [
    'destination',
    'known-bad',
    'known bad',
    'malware',
    'phishing',
    'exfiltration',
    'command-and-control',
  ],
} as const

export type ExtensionConfig = typeof EXTENSION_CONFIG
