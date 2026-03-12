import { spawn } from 'node:child_process';
import type { OAuthClientProvider } from '@modelcontextprotocol/sdk/client/auth.js';
import { auth as mcpAuth } from '@modelcontextprotocol/sdk/client/auth.js';
import type { ServerDefinition } from '../config-schema.js';
import { analyzeConnectionError } from '../error-classifier.js';
import { createCodeExchangeProvider, createManualOAuthSession } from '../oauth.js';
import { parseManualOAuthCallback } from '../oauth-manual.js';
import { buildOAuthPersistence, clearOAuthCaches } from '../oauth-persistence.js';
import type { VaultEntry } from '../oauth-vault.js';
import { findServerNameByState } from '../oauth-vault.js';
import type { createRuntime } from '../runtime.js';
import type { EphemeralServerSpec } from './adhoc-server.js';
import { extractEphemeralServerFlags } from './ephemeral-flags.js';
import { prepareEphemeralServerTarget } from './ephemeral-target.js';
import { looksLikeHttpUrl } from './http-utils.js';
import { buildConnectionIssueEnvelope } from './json-output.js';
import { logInfo, logWarn } from './logger-context.js';
import { consumeOutputFormat } from './output-format.js';

type Runtime = Awaited<ReturnType<typeof createRuntime>>;

export async function handleAuth(runtime: Runtime, args: string[]): Promise<void> {
  // Route `auth complete` before any other flag parsing.
  if (args[0] === 'complete') {
    args.shift();
    return handleAuthComplete(runtime, args);
  }

  const resetIndex = args.indexOf('--reset');
  const shouldReset = resetIndex !== -1;
  if (shouldReset) {
    args.splice(resetIndex, 1);
  }

  // Parse --browser <mode>
  const browserIndex = args.indexOf('--browser');
  let browserMode: 'open' | 'none' = 'open';
  if (browserIndex !== -1) {
    const value = args[browserIndex + 1];
    if (value === 'none') {
      browserMode = 'none';
      args.splice(browserIndex, 2);
    } else if (value === 'open') {
      args.splice(browserIndex, 2);
    } else {
      throw new Error(`Unknown --browser mode: ${String(value)}. Valid values: open, none`);
    }
  }

  const format = consumeOutputFormat(args, {
    defaultFormat: 'text',
    allowed: ['text', 'json'],
    enableRawShortcut: false,
    jsonShortcutFlag: '--json',
  }) as 'text' | 'json';
  const ephemeralSpec: EphemeralServerSpec | undefined = extractEphemeralServerFlags(args);
  let target = args.shift();
  const nameHints: string[] = [];
  if (ephemeralSpec && target && !looksLikeHttpUrl(target)) {
    nameHints.push(target);
  }

  const prepared = await prepareEphemeralServerTarget({
    runtime,
    target,
    ephemeral: ephemeralSpec,
    nameHints,
    reuseFromSpec: true,
  });
  target = prepared.target;

  if (!target) {
    throw new Error('Usage: mcporter auth <server | url> [--http-url <url> | --stdio <command>]');
  }

  const definition = runtime.getDefinition(target);
  if (shouldReset) {
    await clearOAuthCaches(definition);
    logInfo(`Cleared cached credentials for '${target}'.`);
  }

  if (definition.command.kind === 'stdio' && definition.oauthCommand) {
    logInfo(`Starting auth helper for '${target}' (stdio). Leave this running until the browser flow completes.`);
    await runStdioAuth(definition);
    logInfo(`Auth helper for '${target}' finished. You can now call tools.`);
    return;
  }

  if (browserMode === 'none') {
    return runManualBrowserFlow(target, definition);
  }

  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      logInfo(`Initiating OAuth flow for '${target}'...`);
      const tools = await runtime.listTools(target, { autoAuthorize: true });
      logInfo(`Authorization complete. ${tools.length} tool${tools.length === 1 ? '' : 's'} available.`);
      return;
    } catch (error) {
      if (attempt === 0 && shouldRetryAuthError(error)) {
        logWarn('Server signaled OAuth after the initial attempt. Retrying with browser flow...');
        continue;
      }
      const message = error instanceof Error ? error.message : String(error);
      if (format === 'json') {
        const payload = buildConnectionIssueEnvelope({
          server: target,
          error,
          issue: analyzeConnectionError(error),
        });
        console.log(JSON.stringify(payload, null, 2));
        process.exitCode = 1;
        return;
      }
      throw new Error(`Failed to authorize '${target}': ${message}`);
    }
  }
}

// runManualBrowserFlow drives the OAuth initiation without opening a browser.
// It prints the authorization URL and exits; the user completes the flow via `auth complete`.
async function runManualBrowserFlow(target: string, definition: ServerDefinition): Promise<void> {
  if (definition.command.kind !== 'http') {
    throw new Error(`--browser none requires an HTTP server; '${target}' uses ${definition.command.kind} transport.`);
  }
  const logger = makeLogger();
  logInfo(`Starting manual OAuth flow for '${target}'...`);
  const { provider, close } = await createManualOAuthSession(definition, logger);
  try {
    await mcpAuth(provider as OAuthClientProvider, { serverUrl: definition.command.url });
    // auth() calls provider.redirectToAuthorization() which prints the URL, then returns 'REDIRECT'.
    console.log(`Open the URL above in your local browser. When the redirect fails, paste it into:`);
    console.log(`  mcporter auth complete '<pasted-redirect-url>'`);
  } finally {
    await close();
  }
}

// handleAuthComplete exchanges an authorization code captured from a failed browser redirect.
async function handleAuthComplete(runtime: Runtime, args: string[]): Promise<void> {
  const pastedInput = args.shift();
  if (!pastedInput) {
    throw new Error('Usage: mcporter auth complete <pasted-redirect-url>');
  }

  const parsed = parseManualOAuthCallback(pastedInput);

  if (parsed.error) {
    const detail = parsed.errorDescription ? ` — ${parsed.errorDescription}` : '';
    throw new Error(`OAuth error in callback: ${parsed.error}${detail}`);
  }
  if (!parsed.code) {
    throw new Error('No authorization code found in the pasted URL.');
  }
  if (!parsed.state) {
    throw new Error('No OAuth state found in the pasted URL. Cannot identify the pending auth session.');
  }

  const vaultEntry = await findServerNameByState(parsed.state);
  if (!vaultEntry) {
    throw new Error(
      `No pending auth session found matching that state. Did you run 'mcporter auth <server> --browser none' first?`
    );
  }

  const definition = resolveDefinitionForComplete(runtime, vaultEntry);
  if (definition.command.kind !== 'http') {
    throw new Error(`Server '${vaultEntry.serverName}' does not use HTTP transport; cannot complete OAuth manually.`);
  }

  const logger = makeLogger();
  const persistence = await buildOAuthPersistence(definition, logger);
  const clientInfo = await persistence.readClientInfo();
  const redirectUri = (clientInfo as Record<string, unknown> | undefined)?.redirect_uris;
  const redirectUriStr = Array.isArray(redirectUri) ? (redirectUri[0] as string | undefined) : undefined;
  if (!redirectUriStr) {
    throw new Error(
      `No saved client registration for '${definition.name}'. Run 'mcporter auth ${definition.name} --browser none' again to restart the flow.`
    );
  }

  console.log(`Completing authorization for '${definition.name}'...`);
  const provider = await createCodeExchangeProvider(definition, new URL(redirectUriStr), logger);

  await mcpAuth(provider, { serverUrl: definition.command.url, authorizationCode: parsed.code });

  // Clear the state so it can't be replayed.
  await persistence.clear('state');

  console.log(`Authorization complete for '${definition.name}'. You can now use mcporter commands.`);
}

// resolveDefinitionForComplete tries to get the definition from the runtime config; falls back to
// constructing a minimal ad-hoc HTTP definition from the vault entry's serverUrl for transient
// servers (e.g. bare URLs passed directly to `auth --browser none`).
function resolveDefinitionForComplete(runtime: Runtime, entry: VaultEntry): ServerDefinition {
  try {
    return runtime.getDefinition(entry.serverName);
  } catch {
    if (!entry.serverUrl) {
      throw new Error(
        `Server '${entry.serverName}' is not in the current config and has no saved URL. Cannot complete OAuth.`
      );
    }
    return {
      name: entry.serverName,
      command: { kind: 'http', url: new URL(entry.serverUrl) },
      auth: 'oauth',
    };
  }
}

async function runStdioAuth(definition: ServerDefinition): Promise<void> {
  const authArgs = [...(definition.command.kind === 'stdio' ? (definition.command.args ?? []) : [])];
  if (definition.oauthCommand) {
    authArgs.push(...definition.oauthCommand.args);
  }
  return new Promise((resolve, reject) => {
    const child = spawn(definition.command.kind === 'stdio' ? definition.command.command : '', authArgs, {
      stdio: 'inherit',
      cwd: definition.command.kind === 'stdio' ? definition.command.cwd : process.cwd(),
      env: process.env,
    });
    child.on('error', reject);
    child.on('exit', (code) => {
      if (code === 0) {
        resolve();
      } else {
        reject(new Error(`Auth helper exited with code ${code ?? 'null'}`));
      }
    });
  });
}

function shouldRetryAuthError(error: unknown): boolean {
  return analyzeConnectionError(error).kind === 'auth';
}

// makeLogger returns a minimal OAuthLogger that delegates to the CLI logger context.
function makeLogger() {
  return {
    info: (msg: string) => logInfo(msg),
    warn: (msg: string) => logWarn(msg),
    error: (msg: string, err?: unknown) => {
      const detail =
        err instanceof Error
          ? `: ${err.message}`
          : err != null
            ? `: ${typeof err === 'object' ? JSON.stringify(err) : String(err as string)}`
            : '';
      logWarn(`${msg}${detail}`);
    },
  };
}

export function printAuthHelp(): void {
  const lines = [
    'Usage: mcporter auth <server | url> [flags]',
    '       mcporter auth complete <pasted-url-or-query>',
    '',
    'Purpose:',
    '  Run the authentication flow for a server without listing tools.',
    '',
    'Common flags:',
    '  --reset                 Clear cached credentials before re-authorizing.',
    '  --browser <mode>        Browser behavior: open (default) or none.',
    '  --json                  Emit a JSON envelope on failure.',
    '',
    'Ad-hoc targets:',
    '  --http-url <url>        Register an HTTP server for this run.',
    '  --allow-http            Permit plain http:// URLs with --http-url.',
    '  --stdio <command>       Run a stdio MCP server (repeat --stdio-arg for args).',
    '  --stdio-arg <value>     Append args to the stdio command (repeatable).',
    '  --env KEY=value         Inject env vars for stdio servers (repeatable).',
    '  --cwd <path>            Working directory for stdio servers.',
    '  --name <value>          Override the display name for ad-hoc servers.',
    '  --description <text>    Override the description for ad-hoc servers.',
    '  --persist <path>        Write the ad-hoc definition to config/mcporter.json.',
    '  --yes                   Skip confirmation prompts when persisting.',
    '',
    'Examples:',
    '  mcporter auth linear',
    '  mcporter auth linear --browser none',
    '  mcporter auth complete "http://127.0.0.1/callback?code=abc&state=xyz"',
    '  mcporter auth https://mcp.example.com/mcp',
    '  mcporter auth --stdio "npx -y chrome-devtools-mcp@latest"',
    '  mcporter auth --http-url http://localhost:3000/mcp --allow-http',
  ];
  console.error(lines.join('\n'));
}
