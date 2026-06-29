/**
 * SHA-256 primitives for the proof hash chain.
 *
 * Port of `secureSG/audit/chain.py`'s `derive_genesis_hash` and
 * `compute_link_hash`, expressed with Web Crypto so the exact same code runs in
 * the Cloudflare Worker and in the browser (and in Node 18+, for the gallery
 * build and tests). `globalThis.crypto.subtle` is available in all three.
 *
 * The algorithm is pinned to SHA-256, never weakened to MD5/SHA-1.
 */

const HASH_ALGORITHM = 'SHA-256'

const textEncoder = new TextEncoder()

/**
 * Lowercase-hex-encode a digest.
 *
 * Time complexity: O(n) in the number of bytes. Space complexity: O(n).
 *
 * @param bytes - Raw digest bytes (e.g. from `crypto.subtle.digest`).
 * @returns The lowercase hexadecimal string.
 */
export function hexEncode(bytes: ArrayBuffer | Uint8Array): string {
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes)
  let hex = ''
  for (const byte of view) {
    // padStart guarantees two hex chars per byte (0x0a -> "0a").
    hex += byte.toString(16).padStart(2, '0')
  }
  return hex
}

/**
 * Compute the next link in the hash chain:
 * `sha256( utf8(prevHash) ++ payload )`, lowercase hex.
 *
 * The previous hash is concatenated *before* the payload bytes, byte-for-byte
 * matching the Python reference (`digest.update(prev_hash.encode()); ...;
 * digest.update(payload)`).
 *
 * Time complexity: O(p) in the digested byte length (len(prevHash) + payload).
 * Space complexity: O(p) for the concatenation buffer.
 *
 * @param prevHash - Hex digest of the previous link (genesis for link 1).
 * @param payload - Canonical serialized bytes of the current step.
 * @returns Lowercase-hex SHA-256 digest of the concatenation.
 */
export async function computeLinkHash(
  prevHash: string,
  payload: Uint8Array,
): Promise<string> {
  const prefix = textEncoder.encode(prevHash)
  const buffer = new Uint8Array(prefix.length + payload.length)
  buffer.set(prefix, 0)
  buffer.set(payload, prefix.length)
  const digest = await globalThis.crypto.subtle.digest(HASH_ALGORITHM, buffer)
  return hexEncode(digest)
}

/**
 * Derive the genesis link hash from a configured seed: `sha256(utf8(seed))`,
 * lowercase hex. Changing the seed starts a new, independent chain.
 *
 * Time complexity: O(n) in len(seed). Space complexity: O(n).
 *
 * @param seed - Arbitrary seed string.
 * @returns Lowercase-hex SHA-256 digest of the UTF-8 seed.
 */
export async function deriveGenesisHash(seed: string): Promise<string> {
  const digest = await globalThis.crypto.subtle.digest(
    HASH_ALGORITHM,
    textEncoder.encode(seed),
  )
  return hexEncode(digest)
}
