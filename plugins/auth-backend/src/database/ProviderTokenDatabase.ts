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

/**
 * Represents a stored provider token
 * @internal
 */
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

/**
 * Represents a plugin grant to access provider tokens
 * @internal
 */
export type ProviderTokenGrant = {
  userEntityRef: string;
  pluginId: string;
  providerId: string;
  grantedAt: Date;
};

/**
 * Options for storing a provider token
 * @internal
 */
export type StoreTokenOptions = {
  userEntityRef: string;
  providerId: string;
  encryptedRefreshToken?: string;
  encryptedAccessToken?: string;
  grantedScopes?: string;
  accessTokenExpiresAt?: Date;
};

/**
 * Database layer for managing server-side provider token storage
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

  /**
   * Store or replace a provider token for a user+provider pair
   */
  async storeToken(options: StoreTokenOptions): Promise<ProviderToken> {
    const { userEntityRef, providerId } = options;

    await this.#knex.transaction(async trx => {
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

  /**
   * Retrieve a provider token for a user+provider pair
   */
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

  /**
   * Update only the access token fields for an existing token record
   */
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

  /**
   * Delete a token by user and provider
   */
  async deleteToken(userEntityRef: string, providerId: string): Promise<void> {
    await this.#knex<DbProviderTokenRow>(TOKENS_TABLE)
      .where('user_entity_ref', userEntityRef)
      .andWhere('provider_id', providerId)
      .delete();
  }

  /**
   * Delete all tokens for a user, returns the number deleted
   */
  async deleteAllTokens(userEntityRef: string): Promise<number> {
    return await this.#knex<DbProviderTokenRow>(TOKENS_TABLE)
      .where('user_entity_ref', userEntityRef)
      .delete();
  }

  /**
   * List all provider IDs for which a user has stored tokens
   */
  async listProviders(userEntityRef: string): Promise<string[]> {
    const rows = await this.#knex<DbProviderTokenRow>(TOKENS_TABLE)
      .where('user_entity_ref', userEntityRef)
      .select('provider_id');
    return rows.map(r => r.provider_id);
  }

  /**
   * Grant a plugin access to a user's provider token (idempotent)
   */
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
    if (existing) return;
    await this.#knex<DbProviderTokenGrantRow>(GRANTS_TABLE).insert({
      id: uuid(),
      user_entity_ref: userEntityRef,
      plugin_id: pluginId,
      provider_id: providerId,
      granted_at: this.#knex.fn.now(),
    });
  }

  /**
   * Check whether a plugin has been granted access to a user's provider token
   */
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

  /**
   * Revoke a plugin's access to a user's provider token
   */
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

  /**
   * List all grants for a user
   */
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
