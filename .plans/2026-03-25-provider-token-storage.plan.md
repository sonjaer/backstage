# Server-Side Provider Token Storage – Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add server-side storage for OAuth provider tokens (GitHub, Google, etc.) to the Backstage auth backend, with a plugin-level consent model, so that non-browser clients can access provider tokens without cookies.

**Architecture:** New `ProviderTokenDatabase` + `ProviderTokenService` (mirroring `OfflineSessionDatabase` + `OfflineAccessService`). Two new DB tables: `provider_tokens` for encrypted token storage and `provider_token_grants` for plugin consent tracking. Modified `OAuthRouteHandlers` to optionally store tokens server-side after OAuth callback. New REST endpoints for plugins to request provider tokens and for users to manage consent.

**Tech Stack:** TypeScript, Knex (PostgreSQL/SQLite), AES-256-GCM encryption, Express, Backstage backend-plugin-api

**Worktree:** `/Users/sonjae/src/github.com/backstage/backstage-provider-tokens` (branch `feat/provider-token-storage`)

**Key difference from OfflineAccessService:** Provider tokens need two-way encryption (AES-256-GCM), not one-way hashing (scrypt). We need to decrypt stored tokens to pass them to providers. The encryption key comes from config (`auth.providerTokens.encryptionKey`).

---

## File Structure

### New files (auth-backend)

| File                                                                | Responsibility                                                        |
| ------------------------------------------------------------------- | --------------------------------------------------------------------- |
| `plugins/auth-backend/migrations/20260325120000_provider_tokens.js` | DB migration for `provider_tokens` + `provider_token_grants` tables   |
| `plugins/auth-backend/src/database/ProviderTokenDatabase.ts`        | DB layer: CRUD for provider tokens + grants                           |
| `plugins/auth-backend/src/database/ProviderTokenDatabase.test.ts`   | Tests for DB layer                                                    |
| `plugins/auth-backend/src/service/ProviderTokenService.ts`          | Service layer: store, get (with consent check), refresh, grant/revoke |
| `plugins/auth-backend/src/service/ProviderTokenService.test.ts`     | Tests for service layer                                               |
| `plugins/auth-backend/src/lib/tokenEncryption.ts`                   | AES-256-GCM encrypt/decrypt helpers                                   |
| `plugins/auth-backend/src/lib/tokenEncryption.test.ts`              | Tests for encryption                                                  |

### Modified files

| File                                                      | Change                                                    |
| --------------------------------------------------------- | --------------------------------------------------------- |
| `plugins/auth-backend/src/authPlugin.ts`                  | Create `ProviderTokenService`, pass to router             |
| `plugins/auth-backend/src/service/router.ts`              | Mount provider token REST endpoints                       |
| `plugins/auth-node/src/oauth/createOAuthRouteHandlers.ts` | After OAuth callback, optionally store tokens server-side |

---

## Task 1: Token Encryption Helpers

**Files:**

- Create: `plugins/auth-backend/src/lib/tokenEncryption.ts`
- Test: `plugins/auth-backend/src/lib/tokenEncryption.test.ts`

AES-256-GCM with random IV per encryption. Key from config. Format: `base64(iv).base64(authTag).base64(ciphertext)`.

- [ ] **Step 1: Write the failing test**

```typescript
// plugins/auth-backend/src/lib/tokenEncryption.test.ts
import { encryptToken, decryptToken } from './tokenEncryption';

describe('tokenEncryption', () => {
  // 32-byte key for AES-256
  const key = Buffer.from('a'.repeat(64), 'hex').toString('base64');

  it('should round-trip encrypt and decrypt a token', async () => {
    const plaintext = 'gho_abc123_my_github_token';
    const encrypted = encryptToken(plaintext, key);
    expect(encrypted).not.toBe(plaintext);
    expect(encrypted).toContain('.'); // iv.tag.ciphertext format

    const decrypted = decryptToken(encrypted, key);
    expect(decrypted).toBe(plaintext);
  });

  it('should produce different ciphertexts for the same input', () => {
    const plaintext = 'same-token';
    const a = encryptToken(plaintext, key);
    const b = encryptToken(plaintext, key);
    expect(a).not.toBe(b); // random IV each time
  });

  it('should throw on tampered ciphertext', () => {
    const encrypted = encryptToken('token', key);
    const tampered = encrypted.slice(0, -2) + 'xx';
    expect(() => decryptToken(tampered, key)).toThrow();
  });

  it('should throw on wrong key', () => {
    const encrypted = encryptToken('token', key);
    const wrongKey = Buffer.from('b'.repeat(64), 'hex').toString('base64');
    expect(() => decryptToken(encrypted, wrongKey)).toThrow();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/sonjae/src/github.com/backstage/backstage-provider-tokens && CI=1 yarn test plugins/auth-backend/src/lib/tokenEncryption.test.ts`
Expected: FAIL – module not found

- [ ] **Step 3: Write implementation**

```typescript
// plugins/auth-backend/src/lib/tokenEncryption.ts
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;

/**
 * Encrypt a token using AES-256-GCM.
 * Returns: base64(iv).base64(authTag).base64(ciphertext)
 * @internal
 */
export function encryptToken(plaintext: string, keyBase64: string): string {
  const key = Buffer.from(keyBase64, 'base64');
  if (key.length !== 32) {
    throw new Error('Encryption key must be 32 bytes (256 bits)');
  }

  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv(ALGORITHM, key, iv, {
    authTagLength: AUTH_TAG_LENGTH,
  });

  const encrypted = Buffer.concat([
    cipher.update(plaintext, 'utf8'),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();

  return `${iv.toString('base64')}.${authTag.toString(
    'base64',
  )}.${encrypted.toString('base64')}`;
}

/**
 * Decrypt a token encrypted with encryptToken.
 * @internal
 */
export function decryptToken(encrypted: string, keyBase64: string): string {
  const key = Buffer.from(keyBase64, 'base64');
  if (key.length !== 32) {
    throw new Error('Encryption key must be 32 bytes (256 bits)');
  }

  const parts = encrypted.split('.');
  if (parts.length !== 3) {
    throw new Error('Invalid encrypted token format');
  }

  const iv = Buffer.from(parts[0], 'base64');
  const authTag = Buffer.from(parts[1], 'base64');
  const ciphertext = Buffer.from(parts[2], 'base64');

  const decipher = createDecipheriv(ALGORITHM, key, iv, {
    authTagLength: AUTH_TAG_LENGTH,
  });
  decipher.setAuthTag(authTag);

  const decrypted = Buffer.concat([
    decipher.update(ciphertext),
    decipher.final(),
  ]);

  return decrypted.toString('utf8');
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/sonjae/src/github.com/backstage/backstage-provider-tokens && CI=1 yarn test plugins/auth-backend/src/lib/tokenEncryption.test.ts`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
cd /Users/sonjae/src/github.com/backstage/backstage-provider-tokens
git add plugins/auth-backend/src/lib/tokenEncryption.ts plugins/auth-backend/src/lib/tokenEncryption.test.ts
git commit -m "feat(auth-backend): add AES-256-GCM token encryption helpers"
```

---

## Task 2: Database Migration

**Files:**

- Create: `plugins/auth-backend/migrations/20260325120000_provider_tokens.js`

Two tables: `provider_tokens` for encrypted token storage, `provider_token_grants` for plugin consent.

- [ ] **Step 1: Write migration**

```javascript
// plugins/auth-backend/migrations/20260325120000_provider_tokens.js
// @ts-check

/**
 * @param {import('knex').Knex} knex
 */
exports.up = async function up(knex) {
  await knex.schema.createTable('provider_tokens', table => {
    table.comment(
      'Server-side storage for OAuth provider tokens (e.g., GitHub, Google)',
    );

    table
      .string('id')
      .primary()
      .notNullable()
      .comment('Token record ID (UUID)');

    table
      .string('user_entity_ref')
      .notNullable()
      .comment('Backstage user entity reference');

    table
      .string('provider_id')
      .notNullable()
      .comment('OAuth provider identifier (e.g., github, google)');

    table
      .text('encrypted_refresh_token')
      .nullable()
      .comment('AES-256-GCM encrypted provider refresh token');

    table
      .text('encrypted_access_token')
      .nullable()
      .comment('AES-256-GCM encrypted provider access token (cached)');

    table
      .string('granted_scopes')
      .nullable()
      .comment('Space-separated scopes granted by the provider');

    table
      .timestamp('access_token_expires_at', { useTz: true, precision: 0 })
      .nullable()
      .comment('When the cached access token expires');

    table
      .timestamp('created_at', { useTz: true, precision: 0 })
      .notNullable()
      .defaultTo(knex.fn.now())
      .comment('Token creation timestamp');

    table
      .timestamp('last_used_at', { useTz: true, precision: 0 })
      .notNullable()
      .defaultTo(knex.fn.now())
      .comment('Last time token was used');

    table.unique(['user_entity_ref', 'provider_id'], {
      indexName: 'provider_tokens_user_provider_uniq',
    });
    table.index('user_entity_ref', 'provider_tokens_user_idx');
    table.index('provider_id', 'provider_tokens_provider_idx');
  });

  await knex.schema.createTable('provider_token_grants', table => {
    table.comment(
      'Tracks which plugins have user consent to access provider tokens',
    );

    table
      .string('id')
      .primary()
      .notNullable()
      .comment('Grant record ID (UUID)');

    table
      .string('user_entity_ref')
      .notNullable()
      .comment('Backstage user entity reference');

    table
      .string('plugin_id')
      .notNullable()
      .comment('Backstage plugin identifier requesting access');

    table
      .string('provider_id')
      .notNullable()
      .comment('OAuth provider identifier');

    table
      .timestamp('granted_at', { useTz: true, precision: 0 })
      .notNullable()
      .defaultTo(knex.fn.now())
      .comment('When user granted consent');

    table.unique(['user_entity_ref', 'plugin_id', 'provider_id'], {
      indexName: 'provider_token_grants_user_plugin_provider_uniq',
    });
    table.index('user_entity_ref', 'provider_token_grants_user_idx');
  });
};

/**
 * @param {import('knex').Knex} knex
 */
exports.down = async function down(knex) {
  await knex.schema.dropTable('provider_token_grants');
  await knex.schema.dropTable('provider_tokens');
};
```

- [ ] **Step 2: Verify migration runs**

Run: `cd /Users/sonjae/src/github.com/backstage/backstage-provider-tokens && CI=1 yarn test plugins/auth-backend/src/database/ProviderTokenDatabase.test.ts`
(Will fail because the test file doesn't exist yet, but migration will be exercised in Task 3)

- [ ] **Step 3: Commit**

```bash
cd /Users/sonjae/src/github.com/backstage/backstage-provider-tokens
git add plugins/auth-backend/migrations/20260325120000_provider_tokens.js
git commit -m "feat(auth-backend): add provider_tokens and provider_token_grants migrations"
```

---

## Task 3: ProviderTokenDatabase

**Files:**

- Create: `plugins/auth-backend/src/database/ProviderTokenDatabase.ts`
- Test: `plugins/auth-backend/src/database/ProviderTokenDatabase.test.ts`

Mirrors `OfflineSessionDatabase` pattern: Knex-based, snake_case DB rows mapped to camelCase DTOs.

- [ ] **Step 1: Write the failing test**

```typescript
// plugins/auth-backend/src/database/ProviderTokenDatabase.test.ts
import { TestDatabaseId, TestDatabases } from '@backstage/backend-test-utils';
import { Knex } from 'knex';
import { resolvePackagePath } from '@backstage/backend-plugin-api';
import { ProviderTokenDatabase } from './ProviderTokenDatabase';

jest.setTimeout(60_000);

describe('ProviderTokenDatabase', () => {
  const databases = TestDatabases.create();

  async function createDatabase(databaseId: TestDatabaseId) {
    const knex = await databases.init(databaseId);

    await knex.migrate.latest({
      directory: resolvePackagePath(
        '@backstage/plugin-auth-backend',
        'migrations',
      ),
    });

    return {
      knex,
      db: ProviderTokenDatabase.create({ knex }),
    };
  }

  describe.each(databases.eachSupportedId())('%p', databaseId => {
    let knex: Knex;
    let db: ProviderTokenDatabase;

    beforeEach(async () => {
      ({ knex, db } = await createDatabase(databaseId));
    });

    describe('storeToken', () => {
      it('should store a new provider token', async () => {
        const token = await db.storeToken({
          userEntityRef: 'user:default/alice',
          providerId: 'github',
          encryptedRefreshToken: 'encrypted-refresh',
          encryptedAccessToken: 'encrypted-access',
          grantedScopes: 'repo read:user',
          accessTokenExpiresAt: new Date(Date.now() + 3600 * 1000),
        });

        expect(token).toMatchObject({
          userEntityRef: 'user:default/alice',
          providerId: 'github',
          encryptedRefreshToken: 'encrypted-refresh',
          encryptedAccessToken: 'encrypted-access',
          grantedScopes: 'repo read:user',
        });
        expect(token.id).toBeDefined();
        expect(token.createdAt).toBeInstanceOf(Date);
      });

      it('should upsert when same user+provider exists', async () => {
        await db.storeToken({
          userEntityRef: 'user:default/alice',
          providerId: 'github',
          encryptedRefreshToken: 'old-token',
        });

        await db.storeToken({
          userEntityRef: 'user:default/alice',
          providerId: 'github',
          encryptedRefreshToken: 'new-token',
        });

        const token = await db.getToken('user:default/alice', 'github');
        expect(token?.encryptedRefreshToken).toBe('new-token');
      });

      it('should store different providers independently', async () => {
        await db.storeToken({
          userEntityRef: 'user:default/alice',
          providerId: 'github',
          encryptedRefreshToken: 'github-token',
        });

        await db.storeToken({
          userEntityRef: 'user:default/alice',
          providerId: 'google',
          encryptedRefreshToken: 'google-token',
        });

        const github = await db.getToken('user:default/alice', 'github');
        const google = await db.getToken('user:default/alice', 'google');
        expect(github?.encryptedRefreshToken).toBe('github-token');
        expect(google?.encryptedRefreshToken).toBe('google-token');
      });
    });

    describe('getToken', () => {
      it('should return undefined for non-existent token', async () => {
        const token = await db.getToken('user:default/alice', 'github');
        expect(token).toBeUndefined();
      });
    });

    describe('deleteToken', () => {
      it('should delete a token by user and provider', async () => {
        await db.storeToken({
          userEntityRef: 'user:default/alice',
          providerId: 'github',
          encryptedRefreshToken: 'token',
        });

        await db.deleteToken('user:default/alice', 'github');

        const token = await db.getToken('user:default/alice', 'github');
        expect(token).toBeUndefined();
      });
    });

    describe('listProviders', () => {
      it('should list all providers for a user', async () => {
        await db.storeToken({
          userEntityRef: 'user:default/alice',
          providerId: 'github',
          encryptedRefreshToken: 'token',
        });
        await db.storeToken({
          userEntityRef: 'user:default/alice',
          providerId: 'google',
          encryptedRefreshToken: 'token',
        });

        const providers = await db.listProviders('user:default/alice');
        expect(providers.sort()).toEqual(['github', 'google']);
      });
    });

    describe('grants', () => {
      it('should create and check a grant', async () => {
        await db.grantAccess({
          userEntityRef: 'user:default/alice',
          pluginId: 'scaffolder',
          providerId: 'github',
        });

        const hasGrant = await db.hasGrant(
          'user:default/alice',
          'scaffolder',
          'github',
        );
        expect(hasGrant).toBe(true);
      });

      it('should return false when no grant exists', async () => {
        const hasGrant = await db.hasGrant(
          'user:default/alice',
          'scaffolder',
          'github',
        );
        expect(hasGrant).toBe(false);
      });

      it('should revoke a grant', async () => {
        await db.grantAccess({
          userEntityRef: 'user:default/alice',
          pluginId: 'scaffolder',
          providerId: 'github',
        });

        await db.revokeAccess('user:default/alice', 'scaffolder', 'github');

        const hasGrant = await db.hasGrant(
          'user:default/alice',
          'scaffolder',
          'github',
        );
        expect(hasGrant).toBe(false);
      });

      it('should list grants for a user', async () => {
        await db.grantAccess({
          userEntityRef: 'user:default/alice',
          pluginId: 'scaffolder',
          providerId: 'github',
        });
        await db.grantAccess({
          userEntityRef: 'user:default/alice',
          pluginId: 'catalog',
          providerId: 'google',
        });

        const grants = await db.listGrants('user:default/alice');
        expect(grants).toHaveLength(2);
        expect(grants).toEqual(
          expect.arrayContaining([
            expect.objectContaining({
              pluginId: 'scaffolder',
              providerId: 'github',
            }),
            expect.objectContaining({
              pluginId: 'catalog',
              providerId: 'google',
            }),
          ]),
        );
      });

      it('should be idempotent on duplicate grant', async () => {
        await db.grantAccess({
          userEntityRef: 'user:default/alice',
          pluginId: 'scaffolder',
          providerId: 'github',
        });
        // Should not throw
        await db.grantAccess({
          userEntityRef: 'user:default/alice',
          pluginId: 'scaffolder',
          providerId: 'github',
        });

        const grants = await db.listGrants('user:default/alice');
        expect(grants).toHaveLength(1);
      });
    });
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/sonjae/src/github.com/backstage/backstage-provider-tokens && CI=1 yarn test plugins/auth-backend/src/database/ProviderTokenDatabase.test.ts`
Expected: FAIL – module not found

- [ ] **Step 3: Write implementation**

```typescript
// plugins/auth-backend/src/database/ProviderTokenDatabase.ts
import { Knex } from 'knex';
import { v4 as uuid } from 'uuid';

const TOKENS_TABLE = 'provider_tokens';
const GRANTS_TABLE = 'provider_token_grants';

type DbProviderTokenRow = {
  id: string;
  user_entity_ref: string;
  provider_id: string;
  encrypted_refresh_token: string | null;
  encrypted_access_token: string | null;
  granted_scopes: string | null;
  access_token_expires_at: Date | null;
  created_at: Date;
  last_used_at: Date;
};

type DbProviderTokenGrantRow = {
  id: string;
  user_entity_ref: string;
  plugin_id: string;
  provider_id: string;
  granted_at: Date;
};

/** @internal */
export type ProviderToken = {
  id: string;
  userEntityRef: string;
  providerId: string;
  encryptedRefreshToken: string | null;
  encryptedAccessToken: string | null;
  grantedScopes: string | null;
  accessTokenExpiresAt: Date | null;
  createdAt: Date;
  lastUsedAt: Date;
};

/** @internal */
export type ProviderTokenGrant = {
  userEntityRef: string;
  pluginId: string;
  providerId: string;
  grantedAt: Date;
};

/** @internal */
export type StoreTokenOptions = {
  userEntityRef: string;
  providerId: string;
  encryptedRefreshToken?: string;
  encryptedAccessToken?: string;
  grantedScopes?: string;
  accessTokenExpiresAt?: Date;
};

/**
 * Database layer for managing server-side provider tokens and consent grants
 * @internal
 */
export class ProviderTokenDatabase {
  readonly #knex: Knex;

  static create(options: { knex: Knex }) {
    return new ProviderTokenDatabase(options.knex);
  }

  private constructor(knex: Knex) {
    this.#knex = knex;
  }

  async storeToken(options: StoreTokenOptions): Promise<ProviderToken> {
    const { userEntityRef, providerId } = options;

    await this.#knex.transaction(async trx => {
      // Delete existing token for same user+provider (upsert)
      await trx<DbProviderTokenRow>(TOKENS_TABLE)
        .where('user_entity_ref', userEntityRef)
        .andWhere('provider_id', providerId)
        .delete();

      await trx<DbProviderTokenRow>(TOKENS_TABLE).insert({
        id: uuid(),
        user_entity_ref: userEntityRef,
        provider_id: providerId,
        encrypted_refresh_token: options.encryptedRefreshToken ?? null,
        encrypted_access_token: options.encryptedAccessToken ?? null,
        granted_scopes: options.grantedScopes ?? null,
        access_token_expires_at: options.accessTokenExpiresAt ?? null,
        created_at: trx.fn.now(),
        last_used_at: trx.fn.now(),
      });
    });

    const token = await this.getToken(userEntityRef, providerId);
    if (!token) {
      throw new Error('Failed to store provider token');
    }
    return token;
  }

  async getToken(
    userEntityRef: string,
    providerId: string,
  ): Promise<ProviderToken | undefined> {
    const row = await this.#knex<DbProviderTokenRow>(TOKENS_TABLE)
      .where('user_entity_ref', userEntityRef)
      .andWhere('provider_id', providerId)
      .first();

    return row ? this.#mapTokenRow(row) : undefined;
  }

  async updateAccessToken(
    userEntityRef: string,
    providerId: string,
    encryptedAccessToken: string,
    expiresAt: Date,
  ): Promise<void> {
    await this.#knex<DbProviderTokenRow>(TOKENS_TABLE)
      .where('user_entity_ref', userEntityRef)
      .andWhere('provider_id', providerId)
      .update({
        encrypted_access_token: encryptedAccessToken,
        access_token_expires_at: expiresAt,
        last_used_at: this.#knex.fn.now(),
      });
  }

  async deleteToken(userEntityRef: string, providerId: string): Promise<void> {
    await this.#knex<DbProviderTokenRow>(TOKENS_TABLE)
      .where('user_entity_ref', userEntityRef)
      .andWhere('provider_id', providerId)
      .delete();
  }

  async deleteAllTokens(userEntityRef: string): Promise<number> {
    return await this.#knex<DbProviderTokenRow>(TOKENS_TABLE)
      .where('user_entity_ref', userEntityRef)
      .delete();
  }

  async listProviders(userEntityRef: string): Promise<string[]> {
    const rows = await this.#knex<DbProviderTokenRow>(TOKENS_TABLE)
      .where('user_entity_ref', userEntityRef)
      .select('provider_id');

    return rows.map(r => r.provider_id);
  }

  // --- Grants ---

  async grantAccess(options: {
    userEntityRef: string;
    pluginId: string;
    providerId: string;
  }): Promise<void> {
    const { userEntityRef, pluginId, providerId } = options;

    const existing = await this.#knex<DbProviderTokenGrantRow>(GRANTS_TABLE)
      .where('user_entity_ref', userEntityRef)
      .andWhere('plugin_id', pluginId)
      .andWhere('provider_id', providerId)
      .first();

    if (existing) {
      return; // Already granted
    }

    await this.#knex<DbProviderTokenGrantRow>(GRANTS_TABLE).insert({
      id: uuid(),
      user_entity_ref: userEntityRef,
      plugin_id: pluginId,
      provider_id: providerId,
      granted_at: this.#knex.fn.now(),
    });
  }

  async hasGrant(
    userEntityRef: string,
    pluginId: string,
    providerId: string,
  ): Promise<boolean> {
    const row = await this.#knex<DbProviderTokenGrantRow>(GRANTS_TABLE)
      .where('user_entity_ref', userEntityRef)
      .andWhere('plugin_id', pluginId)
      .andWhere('provider_id', providerId)
      .first();

    return !!row;
  }

  async revokeAccess(
    userEntityRef: string,
    pluginId: string,
    providerId: string,
  ): Promise<void> {
    await this.#knex<DbProviderTokenGrantRow>(GRANTS_TABLE)
      .where('user_entity_ref', userEntityRef)
      .andWhere('plugin_id', pluginId)
      .andWhere('provider_id', providerId)
      .delete();
  }

  async listGrants(userEntityRef: string): Promise<ProviderTokenGrant[]> {
    const rows = await this.#knex<DbProviderTokenGrantRow>(GRANTS_TABLE)
      .where('user_entity_ref', userEntityRef)
      .select('*');

    return rows.map(r => ({
      userEntityRef: r.user_entity_ref,
      pluginId: r.plugin_id,
      providerId: r.provider_id,
      grantedAt: new Date(r.granted_at),
    }));
  }

  #mapTokenRow(row: DbProviderTokenRow): ProviderToken {
    return {
      id: row.id,
      userEntityRef: row.user_entity_ref,
      providerId: row.provider_id,
      encryptedRefreshToken: row.encrypted_refresh_token,
      encryptedAccessToken: row.encrypted_access_token,
      grantedScopes: row.granted_scopes,
      accessTokenExpiresAt: row.access_token_expires_at
        ? new Date(row.access_token_expires_at)
        : null,
      createdAt: new Date(row.created_at),
      lastUsedAt: new Date(row.last_used_at),
    };
  }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/sonjae/src/github.com/backstage/backstage-provider-tokens && CI=1 yarn test plugins/auth-backend/src/database/ProviderTokenDatabase.test.ts`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
cd /Users/sonjae/src/github.com/backstage/backstage-provider-tokens
git add plugins/auth-backend/src/database/ProviderTokenDatabase.ts plugins/auth-backend/src/database/ProviderTokenDatabase.test.ts
git commit -m "feat(auth-backend): add ProviderTokenDatabase for server-side provider token storage"
```

---

## Task 4: ProviderTokenService

**Files:**

- Create: `plugins/auth-backend/src/service/ProviderTokenService.ts`
- Test: `plugins/auth-backend/src/service/ProviderTokenService.test.ts`

Orchestrates encryption + DB + consent checks. Mirrors `OfflineAccessService` factory pattern.

- [ ] **Step 1: Write the failing test**

```typescript
// plugins/auth-backend/src/service/ProviderTokenService.test.ts
import { ProviderTokenService } from './ProviderTokenService';
import { ProviderTokenDatabase } from '../database/ProviderTokenDatabase';
import { TestDatabases } from '@backstage/backend-test-utils';
import { resolvePackagePath } from '@backstage/backend-plugin-api';

jest.setTimeout(60_000);

describe('ProviderTokenService', () => {
  const databases = TestDatabases.create();
  // 32-byte key
  const encryptionKey = Buffer.from('a'.repeat(64), 'hex').toString('base64');

  async function setup() {
    const knex = await databases.init('SQLITE_3');
    await knex.migrate.latest({
      directory: resolvePackagePath(
        '@backstage/plugin-auth-backend',
        'migrations',
      ),
    });

    const db = ProviderTokenDatabase.create({ knex });
    const service = new ProviderTokenService({ db, encryptionKey });
    return { knex, db, service };
  }

  it('should store and retrieve a provider token', async () => {
    const { service } = await setup();

    await service.storeProviderToken({
      userEntityRef: 'user:default/alice',
      providerId: 'github',
      refreshToken: 'ghr_secret_refresh_token',
      accessToken: 'gho_secret_access_token',
      scopes: 'repo read:user',
      accessTokenExpiresAt: new Date(Date.now() + 3600 * 1000),
    });

    const result = await service.getProviderToken({
      userEntityRef: 'user:default/alice',
      providerId: 'github',
      pluginId: 'scaffolder',
    });

    // No grant yet – should throw ConsentRequired
    expect(result).toBeUndefined();
  });

  it('should return token when grant exists', async () => {
    const { service } = await setup();

    await service.storeProviderToken({
      userEntityRef: 'user:default/alice',
      providerId: 'github',
      refreshToken: 'ghr_secret',
      accessToken: 'gho_secret',
      scopes: 'repo',
    });

    await service.grantAccess({
      userEntityRef: 'user:default/alice',
      pluginId: 'scaffolder',
      providerId: 'github',
    });

    const result = await service.getProviderToken({
      userEntityRef: 'user:default/alice',
      providerId: 'github',
      pluginId: 'scaffolder',
    });

    expect(result).toBeDefined();
    expect(result!.accessToken).toBe('gho_secret');
    expect(result!.refreshToken).toBe('ghr_secret');
  });

  it('should list grants for a user', async () => {
    const { service } = await setup();

    await service.grantAccess({
      userEntityRef: 'user:default/alice',
      pluginId: 'scaffolder',
      providerId: 'github',
    });

    const grants = await service.listGrants('user:default/alice');
    expect(grants).toHaveLength(1);
    expect(grants[0]).toMatchObject({
      pluginId: 'scaffolder',
      providerId: 'github',
    });
  });

  it('should delete token and associated data', async () => {
    const { service } = await setup();

    await service.storeProviderToken({
      userEntityRef: 'user:default/alice',
      providerId: 'github',
      refreshToken: 'token',
    });

    await service.deleteProviderToken('user:default/alice', 'github');

    const result = await service.getProviderToken({
      userEntityRef: 'user:default/alice',
      providerId: 'github',
      pluginId: 'scaffolder',
    });
    expect(result).toBeUndefined();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/sonjae/src/github.com/backstage/backstage-provider-tokens && CI=1 yarn test plugins/auth-backend/src/service/ProviderTokenService.test.ts`
Expected: FAIL – module not found

- [ ] **Step 3: Write implementation**

```typescript
// plugins/auth-backend/src/service/ProviderTokenService.ts
import { ProviderTokenDatabase } from '../database/ProviderTokenDatabase';
import { encryptToken, decryptToken } from '../lib/tokenEncryption';

/** @internal */
export class ProviderTokenService {
  readonly #db: ProviderTokenDatabase;
  readonly #encryptionKey: string;

  constructor(options: { db: ProviderTokenDatabase; encryptionKey: string }) {
    this.#db = options.db;
    this.#encryptionKey = options.encryptionKey;
  }

  async storeProviderToken(options: {
    userEntityRef: string;
    providerId: string;
    refreshToken?: string;
    accessToken?: string;
    scopes?: string;
    accessTokenExpiresAt?: Date;
  }): Promise<void> {
    await this.#db.storeToken({
      userEntityRef: options.userEntityRef,
      providerId: options.providerId,
      encryptedRefreshToken: options.refreshToken
        ? encryptToken(options.refreshToken, this.#encryptionKey)
        : undefined,
      encryptedAccessToken: options.accessToken
        ? encryptToken(options.accessToken, this.#encryptionKey)
        : undefined,
      grantedScopes: options.scopes,
      accessTokenExpiresAt: options.accessTokenExpiresAt,
    });
  }

  /**
   * Get a provider token for a user, checking plugin consent.
   * Returns undefined if no token exists or no grant for the plugin.
   */
  async getProviderToken(options: {
    userEntityRef: string;
    providerId: string;
    pluginId: string;
  }): Promise<
    { accessToken: string; refreshToken?: string; scopes?: string } | undefined
  > {
    const { userEntityRef, providerId, pluginId } = options;

    // Check consent
    const hasGrant = await this.#db.hasGrant(
      userEntityRef,
      pluginId,
      providerId,
    );
    if (!hasGrant) {
      return undefined;
    }

    const token = await this.#db.getToken(userEntityRef, providerId);
    if (!token) {
      return undefined;
    }

    return {
      accessToken: token.encryptedAccessToken
        ? decryptToken(token.encryptedAccessToken, this.#encryptionKey)
        : '',
      refreshToken: token.encryptedRefreshToken
        ? decryptToken(token.encryptedRefreshToken, this.#encryptionKey)
        : undefined,
      scopes: token.grantedScopes ?? undefined,
    };
  }

  async grantAccess(options: {
    userEntityRef: string;
    pluginId: string;
    providerId: string;
  }): Promise<void> {
    await this.#db.grantAccess(options);
  }

  async revokeAccess(
    userEntityRef: string,
    pluginId: string,
    providerId: string,
  ): Promise<void> {
    await this.#db.revokeAccess(userEntityRef, pluginId, providerId);
  }

  async listGrants(userEntityRef: string) {
    return this.#db.listGrants(userEntityRef);
  }

  async listProviders(userEntityRef: string) {
    return this.#db.listProviders(userEntityRef);
  }

  async deleteProviderToken(
    userEntityRef: string,
    providerId: string,
  ): Promise<void> {
    await this.#db.deleteToken(userEntityRef, providerId);
  }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/sonjae/src/github.com/backstage/backstage-provider-tokens && CI=1 yarn test plugins/auth-backend/src/service/ProviderTokenService.test.ts`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
cd /Users/sonjae/src/github.com/backstage/backstage-provider-tokens
git add plugins/auth-backend/src/service/ProviderTokenService.ts plugins/auth-backend/src/service/ProviderTokenService.test.ts
git commit -m "feat(auth-backend): add ProviderTokenService with consent-gated token access"
```

---

## Task 5: Wire into Auth Plugin + REST Endpoints

**Files:**

- Modify: `plugins/auth-backend/src/authPlugin.ts`
- Modify: `plugins/auth-backend/src/service/router.ts`

Add config-gated `ProviderTokenService` creation and REST endpoints for token management.

- [ ] **Step 1: Add config and service creation to authPlugin.ts**

In `authPlugin.ts`, after the `offlineAccess` creation block (~line 95), add:

```typescript
const providerTokensEnabled = config.getOptionalBoolean(
  'auth.providerTokens.enabled',
);

let providerTokenService: ProviderTokenService | undefined;
if (providerTokensEnabled) {
  const encryptionKey = config.getString('auth.providerTokens.encryptionKey');
  const knex = await database.getClient();
  const db = ProviderTokenDatabase.create({ knex });
  providerTokenService = new ProviderTokenService({
    db,
    encryptionKey,
  });
}
```

Add `providerTokenService` to the `createRouter` call.

- [ ] **Step 2: Add REST endpoints to router.ts**

After the OIDC router mount, add provider token endpoints:

```typescript
if (options.providerTokenService) {
  const providerTokenRouter = Router();
  const pts = options.providerTokenService;

  // Get a provider token (plugin-to-plugin, authenticated)
  providerTokenRouter.get('/v1/provider-token', async (req, res) => {
    const credentials = await httpAuth.credentials(req, {
      allow: ['service'],
    });
    const providerId = req.query.provider as string;
    const pluginId = req.query.plugin as string;
    const userEntityRef = req.query.user as string;

    if (!providerId || !pluginId || !userEntityRef) {
      res
        .status(400)
        .json({ error: 'Missing provider, plugin, or user query parameter' });
      return;
    }

    const result = await pts.getProviderToken({
      userEntityRef,
      providerId,
      pluginId,
    });

    if (!result) {
      res.status(404).json({
        error: 'No token or consent not granted',
        consentRequired: true,
      });
      return;
    }

    res.json({
      accessToken: result.accessToken,
      scopes: result.scopes,
    });
  });

  // Grant consent (user-facing, requires user auth)
  providerTokenRouter.post('/v1/provider-token/grant', async (req, res) => {
    const credentials = await httpAuth.credentials(req, {
      allow: ['user'],
    });
    const userEntityRef = credentials.principal.userEntityRef;
    const { pluginId, providerId } = req.body;

    if (!pluginId || !providerId) {
      res.status(400).json({ error: 'Missing pluginId or providerId' });
      return;
    }

    await pts.grantAccess({ userEntityRef, pluginId, providerId });
    res.status(204).end();
  });

  // Revoke consent
  providerTokenRouter.delete('/v1/provider-token/grant', async (req, res) => {
    const credentials = await httpAuth.credentials(req, {
      allow: ['user'],
    });
    const userEntityRef = credentials.principal.userEntityRef;
    const { pluginId, providerId } = req.body;

    await pts.revokeAccess(userEntityRef, pluginId, providerId);
    res.status(204).end();
  });

  // List grants
  providerTokenRouter.get('/v1/provider-token/grants', async (req, res) => {
    const credentials = await httpAuth.credentials(req, {
      allow: ['user'],
    });
    const userEntityRef = credentials.principal.userEntityRef;
    const grants = await pts.listGrants(userEntityRef);
    res.json({ grants });
  });

  router.use(providerTokenRouter);
}
```

- [ ] **Step 3: Update RouterOptions interface**

Add to `RouterOptions` in `router.ts`:

```typescript
providerTokenService?: ProviderTokenService;
```

- [ ] **Step 4: Run existing tests to ensure no regression**

Run: `cd /Users/sonjae/src/github.com/backstage/backstage-provider-tokens && CI=1 yarn test plugins/auth-backend/src/service/`
Expected: PASS (existing tests still pass)

- [ ] **Step 5: Commit**

```bash
cd /Users/sonjae/src/github.com/backstage/backstage-provider-tokens
git add plugins/auth-backend/src/authPlugin.ts plugins/auth-backend/src/service/router.ts
git commit -m "feat(auth-backend): wire ProviderTokenService into auth plugin with REST endpoints"
```

---

## Task 6: Modify OAuthRouteHandlers to Store Tokens Server-Side

**Files:**

- Modify: `plugins/auth-node/src/oauth/createOAuthRouteHandlers.ts`

After the OAuth callback (`frameHandler`), optionally store the provider tokens server-side in addition to cookies.

- [ ] **Step 1: Add optional providerTokenStore to OAuthRouteHandlersOptions**

```typescript
// Add to OAuthRouteHandlersOptions interface
providerTokenStore?: {
  storeToken(options: {
    userEntityRef: string;
    providerId: string;
    refreshToken?: string;
    accessToken: string;
    scopes: string;
    expiresInSeconds?: number;
  }): Promise<void>;
};
```

- [ ] **Step 2: Store tokens in frameHandler after OAuth callback**

After `result.session.refreshToken` cookie is set (~line 226-233), add:

```typescript
// Store provider tokens server-side if configured
if (options.providerTokenStore && signInResult) {
  try {
    await options.providerTokenStore.storeToken({
      userEntityRef: signInResult.token
        ? JSON.parse(
            Buffer.from(
              signInResult.token.split('.')[1],
              'base64url',
            ).toString(),
          ).sub
        : 'unknown',
      providerId,
      refreshToken: result.session.refreshToken,
      accessToken: result.session.accessToken,
      scopes: grantedScopes,
      expiresInSeconds: result.session.expiresInSeconds,
    });
  } catch (error) {
    // Non-fatal: cookie flow still works as fallback
    // Log error but don't fail the auth flow
  }
}
```

- [ ] **Step 3: Run existing auth-node tests to ensure no regression**

Run: `cd /Users/sonjae/src/github.com/backstage/backstage-provider-tokens && CI=1 yarn test plugins/auth-node/src/oauth/`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
cd /Users/sonjae/src/github.com/backstage/backstage-provider-tokens
git add plugins/auth-node/src/oauth/createOAuthRouteHandlers.ts
git commit -m "feat(auth-node): optionally store provider tokens server-side after OAuth callback"
```

---

## Task 7: Push to Fork

- [ ] **Step 1: Push branch to fork**

```bash
cd /Users/sonjae/src/github.com/backstage/backstage-provider-tokens
git push fork feat/provider-token-storage
```

- [ ] **Step 2: Verify all commits look right**

```bash
git log --oneline origin/master..feat/provider-token-storage
```
