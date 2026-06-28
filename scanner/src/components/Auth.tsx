/**
 * The login / register surface: one centered glass card that switches between
 * the two modes by route (`#login` vs `#register`). On success it refreshes the
 * app-level auth state and redirects to `#dashboard`. Errors from the API are
 * mapped to inline, human messages keyed off the {@link ApiError} status.
 *
 * Login has a second, conditional step: when the server has email two-factor
 * configured, `POST /api/login` returns `{ twoFactor, challengeId, email }`
 * instead of a session, and the card flips to a 6-digit code-entry step. The
 * code is verified via `POST /api/login/verify`; a "Resend code" link rotates to
 * a fresh code. When 2FA is NOT configured, login behaves exactly as before
 * (one step, straight to the dashboard). Register never uses 2FA.
 */

import { useState, type FormEvent } from 'react'
import { motion } from 'motion/react'
import { ShieldCheck, MailCheck } from 'lucide-react'
import { ApiError, login, loginResend, loginVerify, register } from '../api/client'
import type { AuthState } from '../hooks/useAuth'

export type AuthMode = 'login' | 'register'

interface AuthProps {
  mode: AuthMode
  auth: AuthState
}

/**
 * Translate an API failure into the inline message for the current mode. The
 * contract pins specific statuses: 401 (bad creds, login), 409 (email taken,
 * register), 422 (invalid field). Anything else is a generic, honest fallback.
 */
function errorMessage(error: unknown, mode: AuthMode): string {
  if (error instanceof ApiError) {
    if (mode === 'login' && error.status === 401) {
      return 'Invalid email or password.'
    }
    if (mode === 'register' && error.status === 409) {
      return 'That email is already registered.'
    }
    if (error.status === 422) {
      return 'Enter a valid email and a password of at least 8 characters.'
    }
    if (error.status === 502) {
      return 'We could not send your sign-in code. Please try again.'
    }
    if (error.status === 0) {
      return 'Scanner backend unreachable. Please try again.'
    }
  }
  return 'Something went wrong. Please try again.'
}

/** Translate a verify/resend failure into the inline code-step message. */
function codeErrorMessage(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.status === 401) {
      return 'That code is invalid or has expired.'
    }
    if (error.status === 422) {
      return 'Enter the 6-digit code from your email.'
    }
    if (error.status === 0) {
      return 'Scanner backend unreachable. Please try again.'
    }
  }
  return 'Something went wrong. Please try again.'
}

const COPY: Record<AuthMode, {
  eyebrow: string
  title: string
  submit: string
  busy: string
  toggleText: string
  toggleCta: string
  toggleHref: string
}> = {
  login: {
    eyebrow: 'Welcome back',
    title: 'Log in',
    submit: 'Log in',
    busy: 'Logging in…',
    toggleText: 'New to SecureAI?',
    toggleCta: 'Create an account',
    toggleHref: '#register',
  },
  register: {
    eyebrow: 'Get started',
    title: 'Create your account',
    submit: 'Create account',
    busy: 'Creating account…',
    toggleText: 'Already have an account?',
    toggleCta: 'Log in',
    toggleHref: '#login',
  },
}

/** The number of digits in a one-time 2FA code (mirrors the server contract). */
const CODE_LENGTH = 6

/** A pending 2FA challenge: its id and the masked email the code went to. */
interface Challenge {
  challengeId: string
  email: string
}

const cardMotion = {
  initial: { opacity: 0, y: 16 },
  animate: { opacity: 1, y: 0 },
  transition: { duration: 0.4, ease: [0.16, 1, 0.3, 1] as const },
}

const inputClass =
  'rounded-xl bg-white/[0.04] border border-white/10 px-4 py-2.5 text-[14px] text-white placeholder:text-white/30 outline-none focus:border-white/30 transition-colors'

const submitClass =
  'rounded-full bg-white text-black px-6 py-2.5 text-[14px] font-semibold hover:bg-white/90 transition-colors cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed'

export function Auth({ mode, auth }: AuthProps) {
  const copy = COPY[mode]
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  // When set, the login moved to its 2FA code-entry step.
  const [challenge, setChallenge] = useState<Challenge | null>(null)
  const [code, setCode] = useState('')

  const finishLogin = async (): Promise<void> => {
    await auth.refresh()
    window.location.assign('#dashboard')
  }

  const handleSubmit = async (event: FormEvent<HTMLFormElement>): Promise<void> => {
    event.preventDefault()
    setBusy(true)
    setError(null)
    try {
      const credentials = { email, password }
      if (mode === 'register') {
        await register(credentials)
        await finishLogin()
        return
      }
      const result = await login(credentials)
      if ('twoFactor' in result) {
        // 2FA is configured: flip to the code-entry step, no session yet.
        setChallenge({ challengeId: result.challengeId, email: result.email })
        setCode('')
        setBusy(false)
        return
      }
      await finishLogin()
    } catch (caught) {
      setError(errorMessage(caught, mode))
      setBusy(false)
    }
  }

  const handleVerify = async (event: FormEvent<HTMLFormElement>): Promise<void> => {
    event.preventDefault()
    if (challenge === null) {
      return
    }
    setBusy(true)
    setError(null)
    try {
      await loginVerify(challenge.challengeId, code)
      await finishLogin()
    } catch (caught) {
      setError(codeErrorMessage(caught))
      setBusy(false)
    }
  }

  const handleResend = async (): Promise<void> => {
    if (challenge === null || busy) {
      return
    }
    setBusy(true)
    setError(null)
    try {
      const { challengeId } = await loginResend(challenge.challengeId)
      setChallenge({ challengeId, email: challenge.email })
      setCode('')
    } catch (caught) {
      setError(codeErrorMessage(caught))
    } finally {
      setBusy(false)
    }
  }

  // -------------------------------------------------------- 2FA code step ---
  if (mode === 'login' && challenge !== null) {
    return (
      <section className="relative z-10 flex-1 flex items-center justify-center px-6 py-16">
        <motion.div {...cardMotion} className="liquid-glass rounded-3xl w-full max-w-md p-8 flex flex-col gap-6">
          <div className="flex flex-col items-center text-center gap-3">
            <MailCheck className="w-7 h-7 text-allow" />
            <span className="text-[10px] font-mono uppercase tracking-[0.22em] text-white/45">
              Check your email
            </span>
            <h1
              style={{ fontFamily: "'Instrument Serif', serif" }}
              className="text-3xl md:text-[34px] font-medium tracking-[-0.01em] text-white"
            >
              Enter your code
            </h1>
            <p className="text-[13px] text-white/50">
              We sent a 6-digit code to{' '}
              <span className="text-white/80">{challenge.email}</span>.
            </p>
          </div>

          <form onSubmit={handleVerify} className="flex flex-col gap-4" noValidate>
            <label className="flex flex-col gap-1.5">
              <span className="text-[11px] font-mono uppercase tracking-[0.16em] text-white/45">
                Sign-in code
              </span>
              <input
                type="text"
                name="code"
                inputMode="numeric"
                autoComplete="one-time-code"
                aria-label="Sign-in code"
                maxLength={CODE_LENGTH}
                required
                value={code}
                onChange={(event) => setCode(event.target.value.replace(/\D/g, ''))}
                placeholder="000000"
                className={`${inputClass} text-center tracking-[0.5em] font-mono text-lg`}
              />
            </label>

            {error && (
              <p role="alert" className="text-block/90 font-mono text-[12px] leading-snug">
                {error}
              </p>
            )}

            <button type="submit" disabled={busy || code.length !== CODE_LENGTH} className={submitClass}>
              {busy ? 'Verifying…' : 'Verify'}
            </button>
          </form>

          <p className="text-center text-[13px] text-white/50">
            Did not get it?{' '}
            <button
              type="button"
              onClick={handleResend}
              disabled={busy}
              className="text-white hover:text-allow transition-colors disabled:opacity-50 cursor-pointer"
            >
              Resend code
            </button>
          </p>
        </motion.div>
      </section>
    )
  }

  // ----------------------------------------------------- credentials step ---
  return (
    <section className="relative z-10 flex-1 flex items-center justify-center px-6 py-16">
      <motion.div {...cardMotion} className="liquid-glass rounded-3xl w-full max-w-md p-8 flex flex-col gap-6">
        <div className="flex flex-col items-center text-center gap-3">
          <ShieldCheck className="w-7 h-7 text-allow" />
          <span className="text-[10px] font-mono uppercase tracking-[0.22em] text-white/45">
            {copy.eyebrow}
          </span>
          <h1
            style={{ fontFamily: "'Instrument Serif', serif" }}
            className="text-3xl md:text-[34px] font-medium tracking-[-0.01em] text-white"
          >
            {copy.title}
          </h1>
        </div>

        <form onSubmit={handleSubmit} className="flex flex-col gap-4" noValidate>
          <label className="flex flex-col gap-1.5">
            <span className="text-[11px] font-mono uppercase tracking-[0.16em] text-white/45">
              Email
            </span>
            <input
              type="email"
              name="email"
              autoComplete="email"
              required
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              placeholder="you@company.com"
              className={inputClass}
            />
          </label>

          <label className="flex flex-col gap-1.5">
            <span className="text-[11px] font-mono uppercase tracking-[0.16em] text-white/45">
              Password
            </span>
            <input
              type="password"
              name="password"
              autoComplete={mode === 'login' ? 'current-password' : 'new-password'}
              required
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              placeholder="••••••••"
              className={inputClass}
            />
          </label>

          {error && (
            <p role="alert" className="text-block/90 font-mono text-[12px] leading-snug">
              {error}
            </p>
          )}

          <button type="submit" disabled={busy} className={submitClass}>
            {busy ? copy.busy : copy.submit}
          </button>
        </form>

        <p className="text-center text-[13px] text-white/50">
          {copy.toggleText}{' '}
          <a href={copy.toggleHref} className="text-white hover:text-allow transition-colors">
            {copy.toggleCta}
          </a>
        </p>
      </motion.div>
    </section>
  )
}
