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

import {
  RootConfigService,
  LoggerService,
} from '@backstage/backend-plugin-api';
import { ProviderTokenDatabase } from '../database/ProviderTokenDatabase';
import { encryptToken, decryptToken } from '../lib/tokenEncryption';

/** @internal */
export class ProviderTokenService {
  readonly #db: ProviderTokenDatabase;
  readonly #encryptionKey: string;
  readonly #config: RootConfigService;
  readonly #logger: LoggerService;

  static create(options: {
    db: ProviderTokenDatabase;
    encryptionKey: string;
    config: RootConfigService;
    logger: LoggerService;
  }): ProviderTokenService {
    return new ProviderTokenService(options);
  }

  private constructor(options: {
    db: ProviderTokenDatabase;
    encryptionKey: string;
    config: RootConfigService;
    logger: LoggerService;
  }) {
    this.#db = options.db;
    this.#encryptionKey = options.encryptionKey;
    this.#config = options.config;
    this.#logger = options.logger;
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

    let accessToken = token.encryptedAccessToken
      ? decryptToken(token.encryptedAccessToken, this.#encryptionKey)
      : '';

    // Auto-refresh if access token is expired and we have a refresh token
    const isExpired =
      token.accessTokenExpiresAt &&
      new Date(token.accessTokenExpiresAt) < new Date();

    if (isExpired && token.encryptedRefreshToken) {
      const refreshed = await this.#refreshAccessToken(
        providerId,
        decryptToken(token.encryptedRefreshToken, this.#encryptionKey),
      );
      if (refreshed) {
        accessToken = refreshed.accessToken;
        await this.#db.updateAccessToken(
          userEntityRef,
          providerId,
          encryptToken(refreshed.accessToken, this.#encryptionKey),
          refreshed.expiresAt,
        );
        this.#logger.debug(
          `Refreshed access token for ${userEntityRef} / ${providerId}`,
        );
      } else {
        // Refresh failed – token may be revoked
        this.#logger.warn(
          `Failed to refresh token for ${userEntityRef} / ${providerId}, deleting stored token`,
        );
        await this.#db.deleteToken(userEntityRef, providerId);
        return undefined;
      }
    }

    return {
      accessToken,
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

  async #refreshAccessToken(
    providerId: string,
    refreshToken: string,
  ): Promise<{ accessToken: string; expiresAt: Date } | undefined> {
    const providerConfig = this.#config.getOptionalConfig(
      `auth.providerTokens.providers.${providerId}`,
    );
    if (!providerConfig) {
      this.#logger.warn(
        `No config for provider ${providerId}, cannot refresh token`,
      );
      return undefined;
    }

    const tokenUrl = providerConfig.getString('tokenUrl');
    const clientId = providerConfig.getOptionalString('clientId');

    const params = new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
    });
    if (clientId) {
      params.set('client_id', clientId);
    }

    try {
      const response = await fetch(tokenUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: params.toString(),
      });

      if (!response.ok) {
        this.#logger.warn(
          `Token refresh failed for ${providerId}: ${response.status}`,
        );
        return undefined;
      }

      const data = (await response.json()) as {
        access_token: string;
        expires_in?: number;
      };

      return {
        accessToken: data.access_token,
        expiresAt: new Date(Date.now() + (data.expires_in ?? 3600) * 1000),
      };
    } catch (error) {
      this.#logger.warn(`Token refresh error for ${providerId}`, error);
      return undefined;
    }
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
