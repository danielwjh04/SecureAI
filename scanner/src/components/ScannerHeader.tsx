/**
 * The scanner's top bar. Adapted from the dashboard's `AppHeader`: same brand
 * lockup, `.conn` live indicator, and sticky-glass `.header` chrome, but scoped
 * to the Skill Safety Scanner — a fixed brand, a one-line tagline, and a subtle
 * always-on live dot. No navigation and no demo action: this SPA is a single
 * scan surface, so the header only identifies the product and signals liveness.
 *
 * Purely presentational and stateless.
 */

export function ScannerHeader() {
  return (
    <header className="header">
      <div className="header__brand">
        <span className="header__mark" aria-hidden="true">
          <svg
            width="22"
            height="22"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <path d="M12 2 4 5v6c0 5 3.4 8.3 8 11 4.6-2.7 8-6 8-11V5l-8-3Z" />
            <path d="m9 12 2 2 4-4" />
          </svg>
        </span>
        <h1>Skill Safety Scanner</h1>
      </div>
      <p className="header__tagline">Verify a skill before your agent learns it</p>
      <div className="header__right">
        <span className="conn conn--on">
          <span className="conn__dot" />
          Live
        </span>
      </div>
    </header>
  )
}
