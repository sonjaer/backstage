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

import { ProviderTokenDatabase } from '../database/ProviderTokenDatabase';
import { encryptToken, decryptToken } from '../lib/tokenEncryption';

/** @internal */
export class ProviderTokenService {
  readonly #db: ProviderTokenDatabase;
  readonly #encryptionKey: string;

  static create(options: {
    db: ProviderTokenDatabase;
    encryptionKey: string;
  }): ProviderTokenService {
    return new ProviderTokenService(options);
  }

  private constructor(options: {
    db: ProviderTokenDatabase;
    encryptionKey: string;
  }) {
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

  async getProviderTokens(options: {
    userEntityRef: string;
    providerIds: string[];
    pluginId: string;
  }): Promise<
    Record<
      string,
      { accessToken: string; refreshToken?: string; scopes?: string }
    >
  > {
    const result: Record<
      string,
      { accessToken: string; refreshToken?: string; scopes?: string }
    > = {};
    for (const providerId of options.providerIds) {
      const token = await this.getProviderToken({
        userEntityRef: options.userEntityRef,
        providerId,
        pluginId: options.pluginId,
      });
      if (token) {
        result[providerId] = token;
      }
    }
    return result;
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
