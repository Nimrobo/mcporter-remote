import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import http from 'node:http';
import { URL } from 'node:url';
import type { OAuthClientProvider } from '@modelcontextprotocol/sdk/client/auth.js';
import type {
  OAuthClientInformationMixed,
  OAuthClientMetadata,
  OAuthTokens,
} from '@modelcontextprotocol/sdk/shared/auth.js';
import type { ServerDefinition } from './config.js';
import type { OAuthPersistence } from './oauth-persistence.js';
import { buildOAuthPersistence } from './oauth-persistence.js';

const CALLBACK_HOST = '127.0.0.1';
const CALLBACK_PATH = '/callback';

interface Deferred<T> {
  promise: Promise<T>;
  resolve: (value: T) => void;
  reject: (reason?: unknown) => void;
}

// createDeferred produces a minimal promise wrapper for async coordination.
function createDeferred<T>(): Deferred<T> {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

// openExternal attempts to launch the system browser cross-platform.
function openExternal(url: string, platform: NodeJS.Platform = process.platform, launch: typeof spawn = spawn) {
  const stdio = 'ignore';
  try {
    if (platform === 'darwin') {
      const child = launch('open', [url], { stdio, detached: true });
      child.unref();
    } else if (platform === 'win32') {
      const child = launch('cmd', ['/c', 'start', '""', url], {
        stdio,
        detached: true,
      });
      child.unref();
    } else {
      try {
        const child = launch('xdg-open', [url], { stdio, detached: true });
        child.on('error', () => {}); // swallow ENOENT on headless servers
        child.unref();
      } catch {
        // headless server — no browser available
      }
    }
  } catch {
    // best-effort: fall back to printing URL
  }
}

// PersistentOAuthClientProvider persists OAuth session artifacts to disk and captures callback redirects.
class PersistentOAuthClientProvider implements OAuthClientProvider {
  private readonly metadata: OAuthClientMetadata;
  private readonly logger: OAuthLogger;
  private readonly persistence: OAuthPersistence;
  private redirectUrlValue: URL;
  private authorizationDeferred: Deferred<string> | null = null;
  private server?: http.Server;
  private readonly manual: boolean;

  private constructor(
    private readonly definition: ServerDefinition,
    persistence: OAuthPersistence,
    redirectUrl: URL,
    logger: OAuthLogger,
    manual = false
  ) {
    this.manual = manual;
    this.redirectUrlValue = redirectUrl;
    this.logger = logger;
    this.persistence = persistence;
    this.metadata = {
      client_name: definition.clientName ?? `mcporter (${definition.name})`,
      redirect_uris: [this.redirectUrlValue.toString()],
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      token_endpoint_auth_method: 'none',
      // Omit scope so the MCP SDK can derive it from the server's metadata
      // (resource metadata scopes_supported or auth server scopes_supported).
      // Hardcoding 'mcp:tools' breaks providers like Granola whose auth server
      // does not recognise that scope value.
      // If oauthScope is explicitly configured, prefer that exact value.
      ...(definition.oauthScope !== undefined ? { scope: definition.oauthScope || undefined } : {}),
    };
  }

  static async create(
    definition: ServerDefinition,
    logger: OAuthLogger
  ): Promise<{
    provider: PersistentOAuthClientProvider;
    close: () => Promise<void>;
  }> {
    const persistence = await buildOAuthPersistence(definition, logger);

    const server = http.createServer();
    const overrideRedirect = definition.oauthRedirectUrl ? new URL(definition.oauthRedirectUrl) : null;
    const listenHost = overrideRedirect?.hostname ?? CALLBACK_HOST;
    const overridePort = overrideRedirect?.port ?? '';
    const usesDynamicPort = !overrideRedirect || overridePort === '' || overridePort === '0';
    const desiredPort = usesDynamicPort ? undefined : Number.parseInt(overridePort, 10);
    const callbackPath =
      overrideRedirect?.pathname && overrideRedirect.pathname !== '/' ? overrideRedirect.pathname : CALLBACK_PATH;
    const port = await new Promise<number>((resolve, reject) => {
      server.listen(desiredPort ?? 0, listenHost, () => {
        const address = server.address();
        if (typeof address === 'object' && address && 'port' in address) {
          resolve(address.port);
        } else {
          reject(new Error('Failed to determine callback port'));
        }
      });
      server.once('error', (error) => reject(error));
    });

    const redirectUrl = overrideRedirect
      ? new URL(overrideRedirect.toString())
      : new URL(`http://${listenHost}:${port}${callbackPath}`);
    if (usesDynamicPort) {
      redirectUrl.port = String(port);
    }
    if (!overrideRedirect || overrideRedirect.pathname === '/' || overrideRedirect.pathname === '') {
      redirectUrl.pathname = callbackPath;
    }

    // When using a dynamic port, the redirect URI changes every run.  If a
    // previous client registration is cached with a different redirect URI the
    // auth server will reject the request with `invalid_redirect_uri`.  Clear
    // the stale registration so the next flow re-registers with the new URI.
    // Wrapped in try/catch so persistence errors (malformed JSON, permission
    // issues) close the already-bound callback server instead of leaking it.
    if (usesDynamicPort) {
      try {
        const cachedClient = await persistence.readClientInfo();
        const cachedRedirect = firstRedirectUri(cachedClient);
        if (cachedRedirect && cachedRedirect !== redirectUrl.toString()) {
          logger.info(
            `Redirect URI changed (${cachedRedirect} → ${redirectUrl.toString()}); clearing stale client registration.`
          );
          await persistence.clear('client');
        }
      } catch (error) {
        await new Promise<void>((resolve) => {
          server.close(() => resolve());
        });
        throw error;
      }
    }

    const provider = new PersistentOAuthClientProvider(definition, persistence, redirectUrl, logger);
    provider.attachServer(server);
    return {
      provider,
      close: async () => {
        await provider.close();
      },
    };
  }

  // createManual starts the server only to acquire a dynamic port for the redirect URI, then
  // immediately closes it. redirectToAuthorization prints the URL instead of opening a browser,
  // and the process exits after printing — the user completes the flow with `auth complete`.
  static async createManual(
    definition: ServerDefinition,
    logger: OAuthLogger
  ): Promise<{ provider: PersistentOAuthClientProvider; close: () => Promise<void> }> {
    const persistence = await buildOAuthPersistence(definition, logger);

    const server = http.createServer();
    const overrideRedirect = definition.oauthRedirectUrl ? new URL(definition.oauthRedirectUrl) : null;
    const listenHost = overrideRedirect?.hostname ?? CALLBACK_HOST;
    const overridePort = overrideRedirect?.port ?? '';
    const usesDynamicPort = !overrideRedirect || overridePort === '' || overridePort === '0';
    const desiredPort = usesDynamicPort ? undefined : Number.parseInt(overridePort, 10);
    const callbackPath =
      overrideRedirect?.pathname && overrideRedirect.pathname !== '/' ? overrideRedirect.pathname : CALLBACK_PATH;

    const port = await new Promise<number>((resolve, reject) => {
      server.listen(desiredPort ?? 0, listenHost, () => {
        const address = server.address();
        if (typeof address === 'object' && address && 'port' in address) {
          resolve(address.port);
        } else {
          reject(new Error('Failed to determine callback port'));
        }
      });
      server.once('error', (error) => reject(error));
    });

    const redirectUrl = overrideRedirect
      ? new URL(overrideRedirect.toString())
      : new URL(`http://${listenHost}:${port}${callbackPath}`);
    if (usesDynamicPort) {
      redirectUrl.port = String(port);
    }
    if (!overrideRedirect || overrideRedirect.pathname === '/' || overrideRedirect.pathname === '') {
      redirectUrl.pathname = callbackPath;
    }

    // Close the server immediately — manual flow doesn't need a running callback listener.
    await new Promise<void>((resolve) => server.close(() => resolve()));

    if (usesDynamicPort) {
      const cachedClient = await persistence.readClientInfo();
      const cachedRedirect = firstRedirectUri(cachedClient);
      if (cachedRedirect && cachedRedirect !== redirectUrl.toString()) {
        logger.info(
          `Redirect URI changed (${cachedRedirect} → ${redirectUrl.toString()}); clearing stale client registration.`
        );
        await persistence.clear('client');
      }
    }

    const provider = new PersistentOAuthClientProvider(definition, persistence, redirectUrl, logger, true);
    return {
      provider,
      close: async () => {
        // Server is already closed; nothing to do.
      },
    };
  }

  // attachServer listens for the OAuth redirect and resolves/rejects the deferred code promise.
  private attachServer(server: http.Server) {
    this.server = server;
    server.on('request', async (req, res) => {
      try {
        const url = req.url ?? '';
        const parsed = new URL(url, this.redirectUrlValue);
        const expectedPath = this.redirectUrlValue.pathname || '/callback';
        if (parsed.pathname !== expectedPath) {
          res.statusCode = 404;
          res.end('Not found');
          return;
        }
        const code = parsed.searchParams.get('code');
        const error = parsed.searchParams.get('error');
        const receivedState = parsed.searchParams.get('state');
        const expectedState = await this.persistence.readState();
        if (expectedState && receivedState && receivedState !== expectedState) {
          res.statusCode = 400;
          res.setHeader('Content-Type', 'text/html');
          res.end('<html><body><h1>Authorization failed</h1><p>Invalid OAuth state</p></body></html>');
          this.authorizationDeferred?.reject(new Error('Invalid OAuth state'));
          this.authorizationDeferred = null;
          return;
        }
        if (code) {
          this.logger.info(`Received OAuth authorization code for ${this.definition.name}`);
          res.statusCode = 200;
          res.setHeader('Content-Type', 'text/html');
          res.end('<html><body><h1>Authorization successful</h1><p>You can return to the CLI.</p></body></html>');
          this.authorizationDeferred?.resolve(code);
          this.authorizationDeferred = null;
        } else if (error) {
          res.statusCode = 400;
          res.setHeader('Content-Type', 'text/html');
          res.end(`<html><body><h1>Authorization failed</h1><p>${error}</p></body></html>`);
          this.authorizationDeferred?.reject(new Error(`OAuth error: ${error}`));
          this.authorizationDeferred = null;
        } else {
          res.statusCode = 400;
          res.end('Missing authorization code');
          this.authorizationDeferred?.reject(new Error('Missing authorization code'));
          this.authorizationDeferred = null;
        }
      } catch (error) {
        this.authorizationDeferred?.reject(error);
        this.authorizationDeferred = null;
      }
    });
  }

  get redirectUrl(): string | URL {
    return this.redirectUrlValue;
  }

  get clientMetadata(): OAuthClientMetadata {
    return this.metadata;
  }

  async state(): Promise<string> {
    const existing = await this.persistence.readState();
    if (existing) {
      return existing;
    }
    const state = randomUUID();
    await this.persistence.saveState(state);
    return state;
  }

  async clientInformation(): Promise<OAuthClientInformationMixed | undefined> {
    return this.persistence.readClientInfo();
  }

  async saveClientInformation(clientInformation: OAuthClientInformationMixed): Promise<void> {
    await this.persistence.saveClientInfo(clientInformation);
  }

  async tokens(): Promise<OAuthTokens | undefined> {
    return this.persistence.readTokens();
  }

  async saveTokens(tokens: OAuthTokens): Promise<void> {
    await this.persistence.saveTokens(tokens);
    this.logger.info(`Saved OAuth tokens for ${this.definition.name} (${this.persistence.describe()})`);
  }

  async redirectToAuthorization(authorizationUrl: URL): Promise<void> {
    if (this.manual) {
      console.log(`\nAuthorization URL:\n  ${authorizationUrl.toString()}\n`);
      return;
    }
    this.logger.info(`Authorization required for ${this.definition.name}. Opening browser...`);
    this.ensureAuthorizationDeferred();
    __oauthInternals.openExternal(authorizationUrl.toString());
    this.logger.info(`If the browser did not open, visit ${authorizationUrl.toString()} manually.`);
  }

  async saveCodeVerifier(codeVerifier: string): Promise<void> {
    await this.persistence.saveCodeVerifier(codeVerifier);
  }

  async codeVerifier(): Promise<string> {
    const value = await this.persistence.readCodeVerifier();
    if (!value) {
      throw new Error(`Missing PKCE code verifier for ${this.definition.name}`);
    }
    return value.trim();
  }

  // invalidateCredentials removes cached files to force the next OAuth flow.
  async invalidateCredentials(scope: 'all' | 'client' | 'tokens' | 'verifier'): Promise<void> {
    await this.persistence.clear(scope);
  }

  // waitForAuthorizationCode resolves once the local callback server captures a redirect.
  // The same deferred is shared with redirectToAuthorization so callback resolution is stable.
  // In manual mode, throws ManualFlowInitiatedError to signal that the process should exit.
  async waitForAuthorizationCode(): Promise<string> {
    if (this.manual) {
      throw new ManualFlowInitiatedError();
    }
    return this.ensureAuthorizationDeferred().promise;
  }

  // close stops the temporary callback server created for the OAuth session.
  async close(): Promise<void> {
    if (this.authorizationDeferred) {
      // If the CLI is tearing down mid-flow, reject the pending wait promise so runtime shutdown isn't blocked.
      this.authorizationDeferred.reject(new Error('OAuth session closed before receiving authorization code.'));
      this.authorizationDeferred = null;
    }
    if (!this.server) {
      return;
    }
    await new Promise<void>((resolve) => {
      this.server?.close(() => resolve());
    });
    this.server = undefined;
  }

  private ensureAuthorizationDeferred(): Deferred<string> {
    if (!this.authorizationDeferred) {
      this.authorizationDeferred = createDeferred<string>();
    }
    return this.authorizationDeferred;
  }
}

export interface OAuthSession {
  provider: OAuthClientProvider & {
    waitForAuthorizationCode: () => Promise<string>;
  };
  waitForAuthorizationCode: () => Promise<string>;
  close: () => Promise<void>;
}

// createOAuthSession spins up a file-backed OAuth provider and callback server for the target definition.
export async function createOAuthSession(definition: ServerDefinition, logger: OAuthLogger): Promise<OAuthSession> {
  const { provider, close } = await PersistentOAuthClientProvider.create(definition, logger);
  const waitForAuthorizationCode = () => provider.waitForAuthorizationCode();
  return {
    provider,
    waitForAuthorizationCode,
    close,
  };
}
export interface OAuthLogger {
  info(message: string): void;
  warn(message: string): void;
  error(message: string, error?: unknown): void;
}

function firstRedirectUri(client: OAuthClientInformationMixed | undefined): string | undefined {
  if (!client || typeof client !== 'object') {
    return undefined;
  }
  const redirectUris = (client as Record<string, unknown>).redirect_uris;
  if (!Array.isArray(redirectUris)) {
    return undefined;
  }
  const [first] = redirectUris;
  return typeof first === 'string' ? first : undefined;
}

export const __oauthInternals = {
  openExternal,
};

// ManualFlowInitiatedError is thrown by waitForAuthorizationCode() in manual mode to signal
// that the process should exit cleanly after printing the authorization URL.
export class ManualFlowInitiatedError extends Error {
  constructor() {
    super('Manual OAuth flow initiated. Run `mcporter auth complete <pasted-redirect-url>` to finish.');
    this.name = 'ManualFlowInitiatedError';
  }
}

// createManualOAuthSession returns an OAuthClientProvider for --browser none flows.
// It acquires a redirect URI via a short-lived callback server, then closes the server.
// redirectToAuthorization prints the URL instead of opening a browser.
export async function createManualOAuthSession(
  definition: ServerDefinition,
  logger: OAuthLogger
): Promise<{ provider: OAuthClientProvider; close: () => Promise<void> }> {
  return PersistentOAuthClientProvider.createManual(definition, logger);
}

// createCodeExchangeProvider builds a minimal OAuthClientProvider for `auth complete`.
// It reads persisted PKCE and client artifacts to exchange an authorization code for tokens.
export async function createCodeExchangeProvider(
  definition: ServerDefinition,
  redirectUrl: URL,
  logger: OAuthLogger
): Promise<OAuthClientProvider> {
  const persistence = await buildOAuthPersistence(definition, logger);
  const metadata: OAuthClientMetadata = {
    client_name: definition.clientName ?? `mcporter (${definition.name})`,
    redirect_uris: [redirectUrl.toString()],
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
    token_endpoint_auth_method: 'none',
    ...(definition.oauthScope !== undefined ? { scope: definition.oauthScope || undefined } : {}),
  };
  return {
    get redirectUrl() {
      return redirectUrl;
    },
    get clientMetadata() {
      return metadata;
    },
    async state() {
      return (await persistence.readState()) ?? randomUUID();
    },
    async clientInformation() {
      return persistence.readClientInfo();
    },
    async saveClientInformation(info) {
      await persistence.saveClientInfo(info);
    },
    async tokens() {
      return persistence.readTokens();
    },
    async saveTokens(tokens) {
      await persistence.saveTokens(tokens);
      logger.info(`Saved OAuth tokens for ${definition.name} (${persistence.describe()})`);
    },
    async saveCodeVerifier(v) {
      await persistence.saveCodeVerifier(v);
    },
    async codeVerifier() {
      const v = await persistence.readCodeVerifier();
      if (!v) {
        throw new Error(`Missing PKCE code verifier for ${definition.name}`);
      }
      return v.trim();
    },
    async redirectToAuthorization() {
      throw new Error('redirectToAuthorization called unexpectedly during auth complete');
    },
  };
}
