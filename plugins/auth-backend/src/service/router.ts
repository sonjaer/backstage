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

  // Provider token connect session state and helpers.
  // Defined before OidcRouter so the /v1/sessions/pt-* interceptors can
  // be registered first and match before the OIDC session handlers.
  if (options.providerTokenService) {
    // In-memory state for OAuth connect flow (PoC – production would use DB/cache)
    const connectStates = new Map<
      string,
      {
        userEntityRef: string;
        providerId: string;
        pluginId: string;
        codeVerifier: string;
        codeChallenge: string;
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

    // Cache for DCR-registered client IDs (provider -> clientId)
    const dcrClients = new Map<string, string>();

    // Register a client dynamically via OpenID Connect DCR
    const ensureDcrClient = async (
      dcrUrl: string,
      callbackUrl: string,
      providerKey: string,
    ): Promise<string> => {
      const cached = dcrClients.get(providerKey);
      if (cached) return cached;

      const dcrRes = await fetch(dcrUrl, {
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

      if (!dcrRes.ok) {
        const body = await dcrRes.text();
        throw new Error(`DCR registration failed (${dcrRes.status}): ${body}`);
      }

      const data = (await dcrRes.json()) as { client_id: string };
      dcrClients.set(providerKey, data.client_id);
      logger.info(
        `Registered OAuth client via DCR for ${providerKey}: ${data.client_id}`,
      );
      return data.client_id;
    };

    const pts = options.providerTokenService;

    // --- Session endpoints for the existing frontend ConsentPage ---
    // These intercept /v1/sessions/pt-* before the OidcRouter handles the
    // same path pattern for OIDC authorization sessions. Non-pt- session IDs
    // fall through to the OidcRouter via next().

    router.get('/v1/sessions/:sessionId', async (req, res, next) => {
      const { sessionId } = req.params;
      if (!sessionId.startsWith('pt-')) {
        next();
        return;
      }

      const connectSession = connectStates.get(sessionId);
      if (!connectSession || connectSession.expiresAt < Date.now()) {
        connectStates.delete(sessionId);
        res.status(404).json({ error: 'Session not found or expired' });
        return;
      }

      const providerConfig = config.getOptionalConfig(
        `auth.providerTokens.providers.${connectSession.providerId}`,
      );
      const providerLabel =
        providerConfig?.getOptionalString('label') ?? connectSession.providerId;

      // Check if user already has a token for this provider
      // (need user identity from the session – set on approve, but we can check by providerId)
      const existingProviders = connectSession.userEntityRef
        ? await pts.listProviders(connectSession.userEntityRef)
        : [];
      const providerConnected = existingProviders.includes(
        connectSession.providerId,
      );

      const scopeText = providerConnected
        ? `wants to use your ${providerLabel} account`
        : `wants to use your ${providerLabel} account. You haven't connected ${providerLabel} yet. Click Authorize to connect.`;

      res.json({
        id: sessionId,
        clientName: connectSession.pluginId,
        clientId: connectSession.pluginId,
        scope: scopeText,
        redirectUri: `${authUrl}/v1/provider-token/connect/callback`,
        providerConnected,
      });
    });

    router.post('/v1/sessions/:sessionId/approve', async (req, res, next) => {
      const { sessionId } = req.params;
      if (!sessionId.startsWith('pt-')) {
        next();
        return;
      }

      const credentials = await httpAuth.credentials(req);
      if (!options.auth.isPrincipal(credentials, 'user')) {
        res.status(403).json({ error: 'Authentication required' });
        return;
      }

      const connectSession = connectStates.get(sessionId);
      if (!connectSession || connectSession.expiresAt < Date.now()) {
        connectStates.delete(sessionId);
        res.status(404).json({ error: 'Session not found or expired' });
        return;
      }

      // Set user identity from the authenticated request
      connectSession.userEntityRef = credentials.principal.userEntityRef;

      // Check if user already has a token for this provider
      const existingProviders = await pts.listProviders(
        connectSession.userEntityRef,
      );
      if (existingProviders.includes(connectSession.providerId)) {
        // Provider already connected – just store the grant
        await pts.grantAccess({
          userEntityRef: connectSession.userEntityRef,
          pluginId: connectSession.pluginId,
          providerId: connectSession.providerId,
        });
        connectStates.delete(sessionId);
        logger.info(
          `Granted ${connectSession.pluginId} access to ${connectSession.providerId} for ${connectSession.userEntityRef} (provider already connected)`,
        );
        // Return success URL – the ConsentPage will show "completed" state
        res.json({
          redirectUrl: `${appUrl}`,
        });
        return;
      }

      // Provider not connected – build the OAuth authorize URL
      const providerConfig = config.getConfig(
        `auth.providerTokens.providers.${connectSession.providerId}`,
      );
      const authorizeUrl = providerConfig.getString('authorizeUrl');
      const scopes = providerConfig.getOptionalStringArray('scopes') ?? [];
      const callbackUrl = `${authUrl}/v1/provider-token/connect/callback`;

      // Get client ID via DCR or config
      let clientId = providerConfig.getOptionalString('clientId');
      const dcrUrl = providerConfig.getOptionalString('dcrUrl');
      if (!clientId && dcrUrl) {
        clientId = await ensureDcrClient(
          dcrUrl,
          callbackUrl,
          connectSession.providerId,
        );
      }
      if (!clientId) {
        res.status(500).json({ error: 'No client ID available' });
        return;
      }

      // Store clientId and tokenUrl in session for callback
      connectSession.clientId = clientId;
      connectSession.tokenUrl = providerConfig.getString('tokenUrl');

      const params = new URLSearchParams({
        response_type: 'code',
        client_id: clientId,
        redirect_uri: callbackUrl,
        scope: scopes.join(' '),
        state: sessionId,
        code_challenge: connectSession.codeChallenge,
        code_challenge_method: 'S256',
      });

      const audience = providerConfig.getOptionalString('audience');
      if (audience) {
        params.set('audience', audience);
      }

      res.json({
        redirectUrl: `${authorizeUrl}?${params.toString()}`,
      });
    });

    router.post('/v1/sessions/:sessionId/reject', async (req, res, next) => {
      const { sessionId } = req.params;
      if (!sessionId.startsWith('pt-')) {
        next();
        return;
      }

      connectStates.delete(sessionId);
      res.json({ redirectUrl: appUrl });
    });

    // --- OidcRouter (handles non-pt- sessions) ---
    router.use(oidcRouter.getRouter());

    // --- Provider token API endpoints ---
    const providerTokenRouter = Router();

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

    // Connect endpoint – creates a session and redirects to the frontend ConsentPage
    providerTokenRouter.get('/v1/provider-token/connect', async (req, res) => {
      const providerId = req.query.provider as string;
      const pluginId = req.query.plugin as string;
      const redirectUrl = req.query.redirect as string;

      if (!providerId || !pluginId) {
        throw new InputError('Missing provider or plugin query parameter');
      }

      // Generate session ID and PKCE
      const sessionId = `pt-${crypto.randomBytes(16).toString('hex')}`;
      const codeVerifier = crypto.randomBytes(32).toString('base64url');
      const codeChallenge = crypto
        .createHash('sha256')
        .update(codeVerifier)
        .digest('base64url');

      // Store session (user identity will be set when they approve)
      connectStates.set(sessionId, {
        userEntityRef: '', // Set on approve
        providerId,
        pluginId,
        codeVerifier,
        codeChallenge,
        redirectUrl,
        clientId: '', // Set on approve
        tokenUrl: '', // Set on approve
        expiresAt: Date.now() + 10 * 60 * 1000, // 10 min TTL
      });

      // Redirect to the existing ConsentPage
      const consentUrl = new URL(
        `./oauth2/authorize/${sessionId}`,
        appUrl.endsWith('/') ? appUrl : `${appUrl}/`,
      );
      res.redirect(consentUrl.toString());
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

        // Look up state (state is the sessionId, e.g. pt-abc123)
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
  } else {
    // No provider token service – mount OidcRouter without session interceptors
    router.use(oidcRouter.getRouter());
  }

  // Gives a more helpful error message than a plain 404
  router.use('/:provider/', req => {
    const { provider } = req.params;
    throw new NotFoundError(`Unknown auth provider '${provider}'`);
  });

  return router;
}
