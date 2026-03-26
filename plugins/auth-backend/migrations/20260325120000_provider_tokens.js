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
