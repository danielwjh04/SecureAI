import '@testing-library/jest-dom/vitest'
import { afterEach } from 'vitest'
import { cleanup } from '@testing-library/react'
import { webcrypto } from 'node:crypto'

// Proof re-verification hashes via globalThis.crypto.subtle (Web Crypto). jsdom
// does not always expose it, so polyfill from Node's webcrypto when absent.
// This keeps the browser proof tests byte-identical to the Worker.
if (globalThis.crypto?.subtle === undefined) {
  Object.defineProperty(globalThis, 'crypto', {
    value: webcrypto,
    configurable: true,
  })
}

afterEach(() => {
  cleanup()
})
