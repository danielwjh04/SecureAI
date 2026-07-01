import { describe, expect, it } from 'vitest'
import { memoryDatabase } from './memory.test'
import { createFreeUser, sha256Hex } from './accounts'
import {
  DEVICE_CREDENTIAL_PREFIX,
  activeGuardDeviceExists,
  countActiveGuardDevices,
  createGuardDeviceCredential,
  findGuardDeviceByCredential,
  listGuardDevices,
  purgeExpiredGuardDevices,
  revokeGuardDevice,
  touchGuardDeviceCredential,
} from './guardDevices'

function tomorrow(): string {
  return new Date(Date.now() + 86400000).toISOString()
}

describe('guard device credentials', () => {
  it('mints a raw credential once and stores only its SHA-256 digest', async () => {
    const { db, store } = memoryDatabase()
    const { user } = await createFreeUser(db, 'device@example.com')
    const minted = await createGuardDeviceCredential(
      db,
      {
        userId: user.id,
        deviceId: 'dev_one',
        name: 'Laptop',
        integration: 'codex',
        scopes: ['guard:decision'],
        createdAt: '2026-06-30T00:00:00.000Z',
        expiresAt: tomorrow(),
      },
      32,
    )

    expect(minted.credential).toMatch(/^gd_secureai_[0-9a-f]{64}$/)
    const digest = await sha256Hex(minted.credential)
    expect(store.guardDeviceCredentials.has(digest)).toBe(true)
    expect(JSON.stringify([...store.guardDeviceCredentials.entries()])).not.toContain(
      minted.credential,
    )
  })

  it('resolves active unexpired credentials and rejects expired or revoked ones', async () => {
    const { db } = memoryDatabase()
    const { user } = await createFreeUser(db, 'resolve-device@example.com')
    const minted = await createGuardDeviceCredential(
      db,
      {
        userId: user.id,
        deviceId: 'dev_one',
        name: null,
        integration: 'cursor',
        scopes: ['guard:decision'],
        createdAt: '2026-06-30T00:00:00.000Z',
        expiresAt: '2026-07-01T00:00:00.000Z',
      },
      32,
    )

    await expect(
      findGuardDeviceByCredential(db, minted.credential, '2026-06-30T12:00:00.000Z'),
    ).resolves.toMatchObject({
      userId: user.id,
      tier: 'free',
      deviceId: 'dev_one',
      integration: 'cursor',
    })
    await expect(
      findGuardDeviceByCredential(db, minted.credential, '2026-07-02T00:00:00.000Z'),
    ).resolves.toBeNull()

    expect(await revokeGuardDevice(db, user.id, minted.device.id)).toBe(true)
    await expect(
      findGuardDeviceByCredential(db, minted.credential, '2026-06-30T12:00:00.000Z'),
    ).resolves.toBeNull()
  })

  it('findGuardDeviceByCredential returns lastSeenAt', async () => {
    const { db } = memoryDatabase()
    const { user } = await createFreeUser(db, 'last-seen@example.com')
    const minted = await createGuardDeviceCredential(
      db,
      {
        userId: user.id,
        deviceId: 'dev_ls',
        name: null,
        integration: 'claude-code',
        scopes: ['guard:decision'],
        createdAt: '2026-06-30T00:00:00.000Z',
        expiresAt: '2026-07-30T00:00:00.000Z',
      },
      32,
    )

    const fresh = await findGuardDeviceByCredential(db, minted.credential, '2026-06-30T12:00:00.000Z')
    expect(fresh?.lastSeenAt).toBeNull()

    await touchGuardDeviceCredential(db, minted.device.id, '2026-06-30T13:00:00.000Z')

    const seen = await findGuardDeviceByCredential(db, minted.credential, '2026-06-30T14:00:00.000Z')
    expect(seen?.lastSeenAt).toBe('2026-06-30T13:00:00.000Z')
  })

  it('lists devices without exposing raw credentials', async () => {
    const { db } = memoryDatabase()
    const { user } = await createFreeUser(db, 'list-device@example.com')
    const minted = await createGuardDeviceCredential(
      db,
      {
        userId: user.id,
        deviceId: 'dev_list',
        name: 'Work laptop',
        integration: 'claude-code',
        scopes: ['guard:decision'],
        createdAt: '2026-06-30T00:00:00.000Z',
        expiresAt: '2026-07-30T00:00:00.000Z',
      },
      32,
    )

    const devices = await listGuardDevices(db, user.id)
    expect(devices).toHaveLength(1)
    expect(devices[0]).toMatchObject({
      id: minted.device.id,
      deviceId: 'dev_list',
      name: 'Work laptop',
      integration: 'claude-code',
      status: 'active',
    })
    expect(JSON.stringify(devices)).not.toContain(minted.credential)
  })

  it('re-registering the same device and integration revokes the prior active credential and leaves exactly one active', async () => {
    const { db } = memoryDatabase()
    const { user } = await createFreeUser(db, 'rotate@example.com')
    const first = await createGuardDeviceCredential(
      db,
      {
        userId: user.id,
        deviceId: 'dev_rotate',
        name: null,
        integration: 'claude-code',
        scopes: ['guard:decision'],
        createdAt: '2026-06-30T00:00:00.000Z',
        expiresAt: tomorrow(),
      },
      32,
    )
    const second = await createGuardDeviceCredential(
      db,
      {
        userId: user.id,
        deviceId: 'dev_rotate',
        name: null,
        integration: 'claude-code',
        scopes: ['guard:decision'],
        createdAt: '2026-06-30T01:00:00.000Z',
        expiresAt: tomorrow(),
      },
      32,
    )

    const all = await listGuardDevices(db, user.id)
    // Both rows preserved (one active, one revoked).
    expect(all).toHaveLength(2)
    const active = all.filter((d) => d.status === 'active')
    const revoked = all.filter((d) => d.status === 'revoked')
    expect(active).toHaveLength(1)
    expect(revoked).toHaveLength(1)
    // The active row is the new one; the revoked row is the old one.
    expect(active[0]?.id).toBe(second.device.id)
    expect(revoked[0]?.id).toBe(first.device.id)
    // The new credential differs from the old one.
    expect(second.credential).not.toBe(first.credential)
  })

  it('the same device with a different integration keeps both active', async () => {
    const { db } = memoryDatabase()
    const { user } = await createFreeUser(db, 'two-integrations@example.com')
    await createGuardDeviceCredential(
      db,
      {
        userId: user.id,
        deviceId: 'dev_shared',
        name: null,
        integration: 'claude-code',
        scopes: ['guard:decision'],
        createdAt: '2026-06-30T00:00:00.000Z',
        expiresAt: tomorrow(),
      },
      32,
    )
    await createGuardDeviceCredential(
      db,
      {
        userId: user.id,
        deviceId: 'dev_shared',
        name: null,
        integration: 'codex',
        scopes: ['guard:decision'],
        createdAt: '2026-06-30T01:00:00.000Z',
        expiresAt: tomorrow(),
      },
      32,
    )

    const all = await listGuardDevices(db, user.id)
    expect(all).toHaveLength(2)
    expect(all.filter((d) => d.status === 'active')).toHaveLength(2)
  })

  it('countActiveGuardDevices counts only active rows', async () => {
    const { db } = memoryDatabase()
    const { user } = await createFreeUser(db, 'count@example.com')
    const m1 = await createGuardDeviceCredential(
      db,
      {
        userId: user.id,
        deviceId: 'dev_a',
        name: null,
        integration: 'claude-code',
        scopes: ['guard:decision'],
        createdAt: '2026-06-30T00:00:00.000Z',
        expiresAt: tomorrow(),
      },
      32,
    )
    await createGuardDeviceCredential(
      db,
      {
        userId: user.id,
        deviceId: 'dev_b',
        name: null,
        integration: 'claude-code',
        scopes: ['guard:decision'],
        createdAt: '2026-06-30T01:00:00.000Z',
        expiresAt: tomorrow(),
      },
      32,
    )

    expect(await countActiveGuardDevices(db, user.id, new Date().toISOString())).toBe(2)

    // Revoke one; the count drops to 1.
    await revokeGuardDevice(db, user.id, m1.device.id)
    expect(await countActiveGuardDevices(db, user.id, new Date().toISOString())).toBe(1)
  })

  it('countActiveGuardDevices excludes expired-but-unpurged active rows', async () => {
    const { db } = memoryDatabase()
    const { user } = await createFreeUser(db, 'count-expiry@example.com')
    const now = '2026-07-01T00:00:00.000Z'
    await createGuardDeviceCredential(
      db,
      {
        userId: user.id,
        deviceId: 'dev_live',
        name: null,
        integration: 'claude-code',
        scopes: ['guard:decision'],
        createdAt: '2026-06-30T00:00:00.000Z',
        expiresAt: '2026-07-30T00:00:00.000Z',
      },
      32,
    )
    await createGuardDeviceCredential(
      db,
      {
        userId: user.id,
        deviceId: 'dev_expired',
        name: null,
        integration: 'claude-code',
        scopes: ['guard:decision'],
        createdAt: '2026-06-20T00:00:00.000Z',
        expiresAt: '2026-06-25T00:00:00.000Z',
      },
      32,
    )

    // The expired row is still status='active' (not yet purged) but auth rejects
    // it, so it must not consume a cap slot.
    expect(await countActiveGuardDevices(db, user.id, now)).toBe(1)
  })

  it('activeGuardDeviceExists returns true only for a matching active tuple', async () => {
    const { db } = memoryDatabase()
    const { user } = await createFreeUser(db, 'exists@example.com')
    await createGuardDeviceCredential(
      db,
      {
        userId: user.id,
        deviceId: 'dev_x',
        name: null,
        integration: 'claude-code',
        scopes: ['guard:decision'],
        createdAt: '2026-06-30T00:00:00.000Z',
        expiresAt: tomorrow(),
      },
      32,
    )

    expect(await activeGuardDeviceExists(db, user.id, 'dev_x', 'claude-code')).toBe(true)
    expect(await activeGuardDeviceExists(db, user.id, 'dev_x', 'codex')).toBe(false)
    expect(await activeGuardDeviceExists(db, user.id, 'dev_other', 'claude-code')).toBe(false)
  })

  it('purgeExpiredGuardDevices deletes rows expired before the cutoff and keeps active and recently-expired rows', async () => {
    const { db, store } = memoryDatabase()
    const { user } = await createFreeUser(db, 'purge@example.com')

    // Long-expired: expires_at is well before the cutoff.
    await createGuardDeviceCredential(
      db,
      {
        userId: user.id,
        deviceId: 'dev_long_expired',
        name: 'Long expired',
        integration: 'claude-code',
        scopes: ['guard:decision'],
        createdAt: '2026-01-01T00:00:00.000Z',
        expiresAt: '2026-01-10T00:00:00.000Z',
      },
      32,
    )

    // Recently expired: within the grace window (expires_at is between cutoff and now).
    await createGuardDeviceCredential(
      db,
      {
        userId: user.id,
        deviceId: 'dev_recently_expired',
        name: 'Recently expired',
        integration: 'claude-code',
        scopes: ['guard:decision'],
        createdAt: '2026-06-20T00:00:00.000Z',
        expiresAt: '2026-06-28T00:00:00.000Z',
      },
      32,
    )

    // Active: expires in the future.
    await createGuardDeviceCredential(
      db,
      {
        userId: user.id,
        deviceId: 'dev_active',
        name: 'Active device',
        integration: 'claude-code',
        scopes: ['guard:decision'],
        createdAt: '2026-06-30T00:00:00.000Z',
        expiresAt: '2026-09-30T00:00:00.000Z',
      },
      32,
    )

    // Cutoff sits between the long-expired row and the recently-expired row.
    const cutoff = '2026-06-20T00:00:00.000Z'
    const removed = await purgeExpiredGuardDevices(db, cutoff)

    expect(removed).toBe(1)

    const remaining = await listGuardDevices(db, user.id)
    const deviceIds = remaining.map((d) => d.deviceId)
    expect(deviceIds).not.toContain('dev_long_expired')
    expect(deviceIds).toContain('dev_recently_expired')
    expect(deviceIds).toContain('dev_active')
    // Confirm the store also reflects the deletion.
    expect(store.guardDeviceCredentials.size).toBe(2)
  })

  it('the minted credential length reflects the configured byte count', async () => {
    const { db } = memoryDatabase()
    const { user } = await createFreeUser(db, 'bytes@example.com')
    const bytes = 16
    const minted = await createGuardDeviceCredential(
      db,
      {
        userId: user.id,
        deviceId: 'dev_bytes',
        name: null,
        integration: 'claude-code',
        scopes: ['guard:decision'],
        createdAt: '2026-06-30T00:00:00.000Z',
        expiresAt: tomorrow(),
      },
      bytes,
    )
    expect(minted.credential.length).toBe(DEVICE_CREDENTIAL_PREFIX.length + 2 * bytes)
  })
})
