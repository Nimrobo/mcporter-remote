import { execFile } from 'node:child_process';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

const CLI_ENTRY = fileURLToPath(new URL('../dist/cli.js', import.meta.url));
const PNPM_COMMAND = process.platform === 'win32' ? 'cmd.exe' : 'pnpm';
const PNPM_ARGS_PREFIX = process.platform === 'win32' ? ['/d', '/s', '/c', 'pnpm'] : [];

function pnpmArgs(args: string[]): string[] {
  return [...PNPM_ARGS_PREFIX, ...args];
}

async function ensureDistBuilt(): Promise<void> {
  try {
    await fs.access(CLI_ENTRY);
  } catch {
    await new Promise<void>((resolve, reject) => {
      execFile(PNPM_COMMAND, pnpmArgs(['build']), { cwd: process.cwd(), env: process.env }, (error) => {
        if (error) {
          reject(error);
          return;
        }
        resolve();
      });
    });
  }
}

async function runCli(args: string[], configPath: string): Promise<{ stdout: string; stderr: string }> {
  return await new Promise((resolve, reject) => {
    execFile(
      process.execPath,
      [CLI_ENTRY, '--config', configPath, ...args],
      {
        env: { ...process.env, MCPORTER_NO_FORCE_EXIT: '1' },
      },
      (error, stdout, stderr) => {
        if (error) {
          const wrapped = new Error(`${error.message}\nSTDOUT:\n${stdout}\nSTDERR:\n${stderr}`);
          reject(wrapped);
          return;
        }
        resolve({ stdout, stderr });
      }
    );
  });
}

describe('stdio MCP servers (filesystem + memory)', () => {
  let tempDir: string;
  let configPath: string;
  let fsRoot: string;

  const filesystemServerScript = fileURLToPath(new URL('./fixtures/stdio-filesystem-server.mjs', import.meta.url));
  const memoryServerScript = fileURLToPath(new URL('./fixtures/stdio-memory-server.mjs', import.meta.url));

  beforeAll(async () => {
    await ensureDistBuilt();
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'mcporter-stdio-e2e-'));
    fsRoot = path.join(tempDir, 'fs-root');
    await fs.mkdir(fsRoot, { recursive: true });
    await fs.writeFile(path.join(fsRoot, 'hello.txt'), 'hello from stdio mcp\n', 'utf8');
    configPath = path.join(tempDir, 'stdio.config.json');
    await fs.writeFile(
      configPath,
      JSON.stringify(
        {
          mcpServers: {
            'fs-test': {
              description: 'Filesystem MCP for stdio e2e tests',
              command: process.execPath,
              args: [filesystemServerScript, fsRoot],
            },
            'memory-test': {
              description: 'Knowledge graph MCP for stdio e2e tests',
              command: process.execPath,
              args: [memoryServerScript],
            },
          },
        },
        null,
        2
      ),
      'utf8'
    );
  });

  afterAll(async () => {
    await fs.rm(tempDir, { recursive: true, force: true }).catch(() => {});
  });

  it('lists filesystem tools and reads files via stdio MCP', async () => {
    const listResult = await runCli(['list', 'fs-test'], configPath);
    expect(listResult.stdout).toContain('Filesystem MCP for stdio e2e tests');
    const callResult = await runCli(
      [
        'call',
        'fs-test.read_text_file',
        '--output',
        'json',
        '--args',
        JSON.stringify({ path: path.join(fsRoot, 'hello.txt') }),
      ],
      configPath
    );
    expect(callResult.stdout).toContain('hello from stdio mcp');
  }, 20000);

  const memoryTest = process.platform === 'win32' ? it.skip : it;

  memoryTest(
    'creates entities with the memory stdio MCP server',
    async () => {
      const callResult = await runCli(
        [
          'call',
          'memory-test.create_entities',
          '--output',
          'json',
          '--args',
          JSON.stringify({ entities: ['alpha', 'beta'] }),
        ],
        configPath
      );
      const stderrWithoutWarnings = callResult.stderr
        .split('\n')
        .filter((line) => !line.startsWith('(node:') && !line.startsWith('(Use `node'))
        .join('\n')
        .trim();
      expect(stderrWithoutWarnings).toBe('');
      expect(callResult.stdout).not.toContain('Error');
    },
    20000
  );
});
