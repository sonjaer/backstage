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

import crypto from 'node:crypto';
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

    // In-memory state for OAuth connect flow (PoC – production would use DB/cache)
    const connectStates = new Map<
      string,
      {
        userEntityRef: string;
        providerId: string;
        pluginId: string;
        codeVerifier: string;
        clientId: string;
        tokenUrl: string;
        redirectUrl?: string;
        expiresAt: number;
      }
    >();

    // Clean up expired states periodically
    const stateCleanupInterval = setInterval(() => {
      const now = Date.now();
      for (const [key, value] of connectStates) {
        if (value.expiresAt < now) {
          connectStates.delete(key);
        }
      }
    }, 60 * 1000);
    stateCleanupInterval.unref();

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

    // Cache for DCR-registered client IDs (provider → clientId)
    const dcrClients = new Map<string, string>();

    // Register a client dynamically via OpenID Connect DCR
    const ensureDcrClient = async (
      dcrUrl: string,
      callbackUrl: string,
      providerKey: string,
    ): Promise<string> => {
      const cached = dcrClients.get(providerKey);
      if (cached) return cached;

      const res = await fetch(dcrUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client_name: `Backstage Provider Token (${providerKey})`,
          redirect_uris: [callbackUrl],
          token_endpoint_auth_method: 'none',
          grant_types: ['authorization_code', 'refresh_token'],
          response_types: ['code'],
          application_type: 'native',
        }),
      });

      if (!res.ok) {
        const body = await res.text();
        throw new Error(`DCR registration failed (${res.status}): ${body}`);
      }

      const data = (await res.json()) as { client_id: string };
      dcrClients.set(providerKey, data.client_id);
      logger.info(
        `Registered OAuth client via DCR for ${providerKey}: ${data.client_id}`,
      );
      return data.client_id;
    };

    // Connect endpoint – user opens this to authorize a provider
    providerTokenRouter.get('/v1/provider-token/connect', async (req, res) => {
      const credentials = await httpAuth.credentials(req, {
        allow: ['user'],
      });
      const userEntityRef = credentials.principal.userEntityRef;
      const providerId = req.query.provider as string;
      const pluginId = req.query.plugin as string;
      const redirectUrl = req.query.redirect as string;

      if (!providerId || !pluginId) {
        throw new InputError('Missing provider or plugin query parameter');
      }

      // Check for external provider config
      const providerConfig = config.getOptionalConfig(
        `auth.providerTokens.providers.${providerId}`,
      );

      if (!providerConfig) {
        // Could be a registered Backstage provider – redirect to its /start endpoint
        const providerStartUrl = `${authUrl}/${providerId}/start?env=development&origin=${encodeURIComponent(
          appUrl,
        )}`;
        res.redirect(providerStartUrl);
        return;
      }

      // External provider – handle OAuth ourselves
      const authorizeUrl = providerConfig.getString('authorizeUrl');
      const tokenUrl = providerConfig.getString('tokenUrl');
      const scopes = providerConfig.getOptionalStringArray('scopes') ?? [];
      const callbackUrl = `${authUrl}/v1/provider-token/connect/callback`;

      // Get client ID – either static from config or via DCR
      let clientId = providerConfig.getOptionalString('clientId');
      const dcrUrl = providerConfig.getOptionalString('dcrUrl');

      if (!clientId && dcrUrl) {
        clientId = await ensureDcrClient(dcrUrl, callbackUrl, providerId);
      }

      if (!clientId) {
        throw new InputError(
          `Provider ${providerId} requires either clientId or dcrUrl in config`,
        );
      }

      // Generate state
      const state = crypto.randomBytes(32).toString('hex');
      const codeVerifier = crypto.randomBytes(32).toString('base64url');
      const codeChallenge = crypto
        .createHash('sha256')
        .update(codeVerifier)
        .digest('base64url');

      // Store state for callback verification
      connectStates.set(state, {
        userEntityRef,
        providerId,
        pluginId,
        codeVerifier,
        redirectUrl,
        clientId,
        tokenUrl,
        expiresAt: Date.now() + 10 * 60 * 1000, // 10 min TTL
      });

      const params = new URLSearchParams({
        response_type: 'code',
        client_id: clientId,
        redirect_uri: callbackUrl,
        scope: scopes.join(' '),
        state,
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
      });

      // For Auth0, add audience if configured
      const audience = providerConfig.getOptionalString('audience');
      if (audience) {
        params.set('audience', audience);
      }

      res.redirect(`${authorizeUrl}?${params.toString()}`);
    });

    // OAuth callback for external providers
    providerTokenRouter.get(
      '/v1/provider-token/connect/callback',
      async (req, res) => {
        const code = req.query.code as string;
        const state = req.query.state as string;
        const error = req.query.error as string;

        if (error) {
          res.status(400).send(`OAuth error: ${error}`);
          return;
        }

        if (!code || !state) {
          throw new InputError('Missing code or state parameter');
        }

        // Look up state
        const connectState = connectStates.get(state);
        if (!connectState || connectState.expiresAt < Date.now()) {
          connectStates.delete(state);
          res.status(400).send('Invalid or expired state. Please try again.');
          return;
        }
        connectStates.delete(state);

        const {
          userEntityRef,
          providerId,
          pluginId,
          codeVerifier,
          redirectUrl,
          clientId,
          tokenUrl,
        } = connectState;

        const callbackUrl = `${authUrl}/v1/provider-token/connect/callback`;

        // Exchange code for tokens (public client – no secret, uses PKCE)
        const tokenParams = new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          redirect_uri: callbackUrl,
          client_id: clientId,
          code_verifier: codeVerifier,
        });

        const tokenResponse = await fetch(tokenUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: tokenParams.toString(),
        });

        if (!tokenResponse.ok) {
          const errorBody = await tokenResponse.text();
          logger.error(
            `Token exchange failed for provider ${providerId}: ${tokenResponse.status} ${errorBody}`,
          );
          res.status(502).send('Failed to exchange authorization code.');
          return;
        }

        const tokenData = await tokenResponse.json();
        const {
          access_token: accessToken,
          refresh_token: refreshToken,
          scope: grantedScopes,
          expires_in: expiresIn,
        } = tokenData as {
          access_token: string;
          refresh_token?: string;
          scope?: string;
          expires_in?: number;
        };

        // Store token + grant atomically
        await pts.storeProviderToken({
          userEntityRef,
          providerId,
          accessToken,
          refreshToken,
          scopes: grantedScopes,
          accessTokenExpiresAt: expiresIn
            ? new Date(Date.now() + expiresIn * 1000)
            : undefined,
        });

        await pts.grantAccess({ userEntityRef, pluginId, providerId });

        logger.info(
          `Stored provider token for ${userEntityRef} / ${providerId} (plugin: ${pluginId})`,
        );

        if (redirectUrl) {
          res.redirect(redirectUrl);
        } else {
          res.send(
            '<html><body><h2>Connected!</h2><p>You can close this tab and return to your application.</p></body></html>',
          );
        }
      },
    );

    router.use(providerTokenRouter);
  }

  // Gives a more helpful error message than a plain 404
  router.use('/:provider/', req => {
    const { provider } = req.params;
    throw new NotFoundError(`Unknown auth provider '${provider}'`);
  });

  return router;
}
