/*
 * Copyright 2026 The Backstage Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
    return { knex, db: ProviderTokenDatabase.create({ knex }) };
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
