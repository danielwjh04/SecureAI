/**
 * `POST /api/guard` handler — the server side of the Claude Code PreToolUse
 * guard. Validates the hook payload with Zod at the edge, builds the same
 * inference client `/api/scan` uses, runs {@link guardDecision}, and returns the
 * resulting {@link GuardDecision} as JSON.
 *
 * The decision IS the body: a clean allow / ask / deny is a 200 with the
 * decision in the payload — that is not a failure. Only a genuine fault (invalid
 * body, config error, transport failure surfaced as a typed error) maps to a
 * non-200 status. Never a silent 200 on internal failure; `guardDecision` itself
 * is fail-closed and only ever returns a decision, so an internal scan fault
 * becomes a `deny` decision at 200, while a malformed request body is a 422.
 */

import type { Env, ScannerConfig } from '../config/env'
import type { GuardDecision } from '../guard/claudeCode'
import type { PreToolUsePayload } from '../schemas/validate'
import {
  ConfigError,
  InferenceError,
  ParseError,
  RedirectResolutionError,
  ReputationError,
  ScannerError,
  SourceResolutionError,
} from '../errors'
import { guardDecision } from '../guard/claudeCode'
import { buildInferenceClient, type AiRunner } from '../pipeline/inference'
import { preToolUseSchema } from '../schemas/validate'

const STATUS_OK = 200
const STATUS_BAD_REQUEST = 400
const STATUS_UNPROCESSABLE = 422
const STATUS_SERVER_ERROR = 500
const STATUS_BAD_GATEWAY = 502

/**
 * Parse and Zod-validate the JSON body into a {@link PreToolUsePayload}. A body
 * that is not JSON, or fails the PreToolUse schema, is a {@link ParseError}
 * (mapped to 422), never an unhandled throw.
 *
 * Time complexity: O(b) in the body byte length. Space complexity: O(b).
 *
 * @throws {ParseError} On non-JSON or schema-invalid input.
 */
async function parseGuardBody(request: Request): Promise<PreToolUsePayload> {
  let raw: unknown
  try {
    raw = await request.json()
  } catch (error: unknown) {
    throw new ParseError('request body is not valid JSON', { cause: error })
  }
  const parsed = preToolUseSchema.safeParse(raw)
  if (!parsed.success) {
    throw new ParseError(`invalid PreToolUse payload: ${parsed.error.message}`)
  }
  return parsed.data
}

/**
 * Map a thrown error to its HTTP status — identical contract to `routes/scan.ts`
 * so the two routes behave uniformly: ParseError / SourceResolutionError → 422;
 * ConfigError → 500; ReputationError / RedirectResolutionError / InferenceError
 * → 502; any other ScannerError → 400; anything else → 500.
 *
 * Time complexity: O(1). Space complexity: O(1).
 */
function statusForError(error: unknown): number {
  if (error instanceof ParseError || error instanceof SourceResolutionError) {
    return STATUS_UNPROCESSABLE
  }
  if (error instanceof ConfigError) {
    return STATUS_SERVER_ERROR
  }
  if (
    error instanceof ReputationError ||
    error instanceof RedirectResolutionError ||
    error instanceof InferenceError
  ) {
    return STATUS_BAD_GATEWAY
  }
  if (error instanceof ScannerError) {
    return STATUS_BAD_REQUEST
  }
  return STATUS_SERVER_ERROR
}

/**
 * Handle `POST /api/guard`. Builds the Workers AI inference client only when the
 * `AI` binding is present (no binding → `null`, handled fail-closed inside
 * `runScan`), exactly as `/api/scan` does. `scannedAt` is stamped here at the
 * edge so the time-varying value never enters the hashed proof. A successful
 * call returns the {@link GuardDecision} at 200 — the allow/ask/deny lives in the
 * body. Only a malformed request body or a typed fault maps to a non-200.
 *
 * Time complexity: dominated by `guardDecision` → `runScan` (O(U·H + R + F)).
 * Space complexity: O(decision size).
 */
export async function handleGuard(
  request: Request,
  env: Env,
  config: ScannerConfig,
): Promise<Response> {
  try {
    const payload = await parseGuardBody(request)

    const inference =
      env.AI !== undefined && env.AI !== null
        ? // The Workers AI binding's `run` is structurally an AiRunner.
          buildInferenceClient(env.AI as unknown as AiRunner, config)
        : null

    const decision: GuardDecision = await guardDecision(payload, {
      config,
      reputation: null, // indicator-feed client lands with the D1 cache
      inference,
      scannedAt: new Date().toISOString(),
      githubToken: typeof env.GITHUB_TOKEN === 'string' ? env.GITHUB_TOKEN : undefined,
    })

    return Response.json(decision, { status: STATUS_OK })
  } catch (error: unknown) {
    const className = error instanceof Error ? error.constructor.name : typeof error
    const message = error instanceof Error ? error.message : String(error)
    console.error(`[handleGuard] ${className}: ${message}`)
    return Response.json({ error: className, message }, { status: statusForError(error) })
  }
}
