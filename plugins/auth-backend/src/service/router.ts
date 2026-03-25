/*
 * Copyright 2020 The Backstage Authors
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

import express from 'express';
import Router from 'express-promise-router';
import cookieParser from 'cookie-parser';
import {
  AuthService,
  DatabaseService,
  DiscoveryService,
  HttpAuthService,
  LoggerService,
  RootConfigService,
} from '@backstage/backend-plugin-api';
import { AuthOwnershipResolver } from '@backstage/plugin-auth-node';
import { CatalogService } from '@backstage/plugin-catalog-node';
import { InputError, NotFoundError } from '@backstage/errors';
import { KeyStores } from '../identity/KeyStores';
import { TokenFactory } from '../identity/TokenFactory';
import { UserInfoDatabase } from '../database/UserInfoDatabase';
import session from 'express-session';
import connectSessionKnex from 'connect-session-knex';
import passport from 'passport';
import { AuthDatabase } from '../database/AuthDatabase';
import { readBackstageTokenExpiration } from './readTokenExpiration';
import { TokenIssuer } from '../identity/types';
import { StaticTokenIssuer } from '../identity/StaticTokenIssuer';
import { StaticKeyStore } from '../identity/StaticKeyStore';
import { bindProviderRouters, ProviderFactories } from '../providers/router';
import { OidcRouter } from './OidcRouter';
import { OidcDatabase } from '../database/OidcDatabase';
import { OfflineAccessService } from './OfflineAccessService';
import { ProviderTokenService } from './ProviderTokenService';

interface RouterOptions {
  logger: LoggerService;
  database: DatabaseService;
  config: RootConfigService;
  discovery: DiscoveryService;
  auth: AuthService;
  tokenFactoryAlgorithm?: string;
  providerFactories?: ProviderFactories;
  catalog: CatalogService;
  ownershipResolver?: AuthOwnershipResolver;
  httpAuth: HttpAuthService;
  offlineAccess?: OfflineAccessService;
  providerTokenService?: ProviderTokenService;
}

export async function createRouter(
  options: RouterOptions,
): Promise<express.Router> {
  const {
    logger,
    config,
    discovery,
    database: db,
    tokenFactoryAlgorithm,
    providerFactories = {},
    httpAuth,
  } = options;

  const router = Router();

  const appUrl = config.getString('app.baseUrl');
  const authUrl = await discovery.getExternalBaseUrl('auth');
  const backstageTokenExpiration = readBackstageTokenExpiration(config);
  const database = AuthDatabase.create(db);

  const keyStore = await KeyStores.fromConfig(config, {
    logger,
    database,
  });

  const userInfo = await UserInfoDatabase.create({
    database,
  });

  const omitClaimsFromToken =
    config.getOptionalBoolean('auth.omitIdentityTokenOwnershipClaim') ?? true
      ? ['ent']
      : [];

  let tokenIssuer: TokenIssuer;
  if (keyStore instanceof StaticKeyStore) {
    tokenIssuer = new StaticTokenIssuer(
      {
        logger: logger.child({ component: 'token-factory' }),
        issuer: authUrl,
        sessionExpirationSeconds: backstageTokenExpiration,
        omitClaimsFromToken,
      },
      keyStore as StaticKeyStore,
    );
  } else {
    tokenIssuer = new TokenFactory({
      issuer: authUrl,
      keyStore,
      keyDurationSeconds: backstageTokenExpiration,
      logger: logger.child({ component: 'token-factory' }),
      algorithm:
        tokenFactoryAlgorithm ??
        config.getOptionalString('auth.identityTokenAlgorithm'),
      omitClaimsFromToken,
    });
  }

  const secret = config.getOptionalString('auth.session.secret');
  if (secret) {
    router.use(cookieParser(secret));
    const enforceCookieSSL = authUrl.startsWith('https');
    const KnexSessionStore = connectSessionKnex(session);
    router.use(
      session({
        secret,
        saveUninitialized: false,
        resave: false,
        cookie: { secure: enforceCookieSSL ? 'auto' : false },
        store: new KnexSessionStore({
          createtable: false,
          knex: await database.get(),
        }),
      }),
    );
    router.use(passport.initialize());
    router.use(passport.session());
  } else {
    router.use(cookieParser());
  }

  router.use(express.urlencoded({ extended: false }));
  router.use(express.json());

  bindProviderRouters(router, {
    providers: providerFactories,
    appUrl,
    baseUrl: authUrl,
    tokenIssuer,
    ...options,
    auth: options.auth,
    userInfo,
  });

  const oidc = await OidcDatabase.create({ database });

  const oidcRouter = OidcRouter.create({
    auth: options.auth,
    tokenIssuer,
    baseUrl: authUrl,
    appUrl,
    userInfo,
    oidc,
    logger,
    httpAuth,
    config,
    offlineAccess: options.offlineAccess,
  });

  router.use(oidcRouter.getRouter());

  if (options.providerTokenService) {
    const providerTokenRouter = Router();
    const pts = options.providerTokenService;

    // Get a provider token (service-to-service or user requesting own tokens)
    providerTokenRouter.get('/v1/provider-token', async (req, res) => {
      const credentials = await httpAuth.credentials(req, {
        allow: ['service', 'user'],
      });
      const providerParam = req.query.provider as string;
      const pluginId = req.query.plugin as string;

      // For user credentials, use the authenticated user; for service, require explicit user param
      let userEntityRef: string;
      if (credentials.principal.type === 'user') {
        userEntityRef = credentials.principal.userEntityRef;
      } else {
        userEntityRef = req.query.user as string;
        if (!userEntityRef) {
          throw new InputError(
            'Missing user query parameter for service credentials',
          );
        }
      }

      if (!providerParam || !pluginId) {
        throw new InputError('Missing provider or plugin query parameter');
      }

      const providerIds = providerParam
        .split(',')
        .map(p => p.trim())
        .filter(Boolean);
      const tokens = await pts.getProviderTokens({
        userEntityRef,
        providerIds,
        pluginId,
      });

      if (Object.keys(tokens).length === 0) {
        const missingProviders: Record<string, { connectUrl: string }> = {};
        for (const id of providerIds) {
          missingProviders[id] = {
            connectUrl: `/api/auth/v1/provider-token/connect?provider=${encodeURIComponent(
              id,
            )}&plugin=${encodeURIComponent(pluginId)}`,
          };
        }
        res.status(404).json({
          error: 'No token found for one or more providers',
          missingProviders,
        });
        return;
      }

      // Check if some providers are missing
      const missingIds = providerIds.filter(id => !tokens[id]);
      const response: Record<string, unknown> = { tokens };
      if (missingIds.length > 0) {
        const missingProviders: Record<string, { connectUrl: string }> = {};
        for (const id of missingIds) {
          missingProviders[id] = {
            connectUrl: `/api/auth/v1/provider-token/connect?provider=${encodeURIComponent(
              id,
            )}&plugin=${encodeURIComponent(pluginId)}`,
          };
        }
        response.missingProviders = missingProviders;
      }

      res.json(response);
    });

    // Grant consent (user-facing)
    providerTokenRouter.post('/v1/provider-token/grant', async (req, res) => {
      const credentials = await httpAuth.credentials(req, {
        allow: ['user'],
      });
      const userEntityRef = credentials.principal.userEntityRef;
      const { pluginId, providerId } = req.body;

      if (!pluginId || !providerId) {
        throw new InputError('Missing pluginId or providerId');
      }

      await pts.grantAccess({ userEntityRef, pluginId, providerId });
      res.status(204).end();
    });

    // Revoke consent
    providerTokenRouter.delete('/v1/provider-token/grant', async (req, res) => {
      const credentials = await httpAuth.credentials(req, { allow: ['user'] });
      const userEntityRef = credentials.principal.userEntityRef;
      const pluginId = req.query.plugin as string;
      const providerId = req.query.provider as string;

      if (!pluginId || !providerId) {
        throw new InputError('Missing plugin or provider query parameter');
      }

      await pts.revokeAccess(userEntityRef, pluginId, providerId);
      res.status(204).end();
    });

    // List grants for current user
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

  // Gives a more helpful error message than a plain 404
  router.use('/:provider/', req => {
    const { provider } = req.params;
    throw new NotFoundError(`Unknown auth provider '${provider}'`);
  });

  return router;
}
