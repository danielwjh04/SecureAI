/**
 * Type declarations for the shared guard-adapter redaction module. The runtime
 * is plain ESM (integrations/shared/secureai-redact.mjs), inlined into each
 * standalone adapter; this file types its public surface so TypeScript callers
 * (for example the Worker schema tests) can consume it without an implicit any.
 */

export const REDACTED: string
export const DEFAULT_PRIVACY_MODE: string
export const PRIVACY_MODES: ReadonlySet<string>

export function redactString(value: string): string
export function redactSecrets(value: unknown): unknown
export function computeContentHash(payload: Record<string, unknown>): string
export function applyPrivacyMode(payload: unknown, mode: string): unknown
