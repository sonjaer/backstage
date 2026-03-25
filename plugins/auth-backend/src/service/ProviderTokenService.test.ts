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
    const service = ProviderTokenService.create({ db, encryptionKey });
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

    // No grant yet - should return undefined
    const result = await service.getProviderToken({
      userEntityRef: 'user:default/alice',
      providerId: 'github',
      pluginId: 'scaffolder',
    });

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

  it('should return tokens for multiple providers via getProviderTokens', async () => {
    const { service } = await setup();

    await service.storeProviderToken({
      userEntityRef: 'user:default/alice',
      providerId: 'github',
      accessToken: 'gho_github_token',
      scopes: 'repo',
    });
    await service.storeProviderToken({
      userEntityRef: 'user:default/alice',
      providerId: 'google',
      accessToken: 'google_token',
      scopes: 'email',
    });

    await service.grantAccess({
      userEntityRef: 'user:default/alice',
      pluginId: 'scaffolder',
      providerId: 'github',
    });
    // No grant for google

    const result = await service.getProviderTokens({
      userEntityRef: 'user:default/alice',
      providerIds: ['github', 'google'],
      pluginId: 'scaffolder',
    });

    expect(result).toHaveProperty('github');
    expect(result.github.accessToken).toBe('gho_github_token');
    expect(result).not.toHaveProperty('google');
  });

  it('should return empty object from getProviderTokens when no grants exist', async () => {
    const { service } = await setup();

    await service.storeProviderToken({
      userEntityRef: 'user:default/alice',
      providerId: 'github',
      accessToken: 'gho_token',
    });

    const result = await service.getProviderTokens({
      userEntityRef: 'user:default/alice',
      providerIds: ['github', 'google'],
      pluginId: 'scaffolder',
    });

    expect(result).toEqual({});
  });

  it('should delete token and associated data', async () => {
    const { service } = await setup();

    await service.storeProviderToken({
      userEntityRef: 'user:default/alice',
      providerId: 'github',
      refreshToken: 'token',
    });

    await service.grantAccess({
      userEntityRef: 'user:default/alice',
      pluginId: 'scaffolder',
      providerId: 'github',
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
