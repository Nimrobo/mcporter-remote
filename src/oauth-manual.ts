import { URL } from 'node:url';

export interface ParsedManualOAuthCallback {
  readonly code?: string;
  readonly state?: string;
  readonly error?: string;
  readonly errorDescription?: string;
  readonly callbackUrl?: string;
}

export function parseManualOAuthCallback(input: string): ParsedManualOAuthCallback {
  const normalized = normalizeManualInput(input);
  const candidates = extractUrlCandidates(normalized);

  for (const candidate of candidates) {
    const parsed = tryParseUrlPayload(candidate);
    if (parsed) {
      return parsed;
    }
  }

  const inline = tryParseQueryPayload(normalized);
  if (inline) {
    return inline;
  }

  throw new Error(
    'Could not extract OAuth callback details. Paste the full redirected URL, the raw query string, or browser text containing the URL.'
  );
}

function normalizeManualInput(input: string): string {
  return input
    .trim()
    .replace(/^['"`<([]+/, '')
    .replace(/['"`>\])\s.,;:!?]+$/, '')
    .replace(/&amp;/gi, '&');
}

function extractUrlCandidates(input: string): string[] {
  const matches = input.match(/https?:\/\/[^\s"'<>]+/gi) ?? [];
  if (matches.length > 0) {
    return matches.map((match) => sanitizeUrlCandidate(match));
  }
  if (input.startsWith('http://') || input.startsWith('https://')) {
    return [sanitizeUrlCandidate(input)];
  }
  return [];
}

function sanitizeUrlCandidate(value: string): string {
  return value.replace(/[),.;]+$/, '').replace(/&amp;/gi, '&');
}

function tryParseUrlPayload(value: string): ParsedManualOAuthCallback | undefined {
  try {
    const url = new URL(value);
    return extractPayload(url, value);
  } catch {
    return undefined;
  }
}

function tryParseQueryPayload(value: string): ParsedManualOAuthCallback | undefined {
  const query = value.startsWith('?') ? value.slice(1) : value;
  if (!query.includes('=')) {
    return undefined;
  }
  const params = new URLSearchParams(query);
  const payload = extractParams(params);
  return payload ? { ...payload } : undefined;
}

function extractPayload(url: URL, callbackUrl: string): ParsedManualOAuthCallback | undefined {
  const direct = extractParams(url.searchParams);
  if (direct) {
    return { ...direct, callbackUrl };
  }
  if (url.hash.startsWith('#')) {
    const hashParams = new URLSearchParams(url.hash.slice(1));
    const hashed = extractParams(hashParams);
    if (hashed) {
      return { ...hashed, callbackUrl };
    }
  }
  return undefined;
}

function extractParams(params: URLSearchParams): Omit<ParsedManualOAuthCallback, 'callbackUrl'> | undefined {
  const code = params.get('code') ?? undefined;
  const state = params.get('state') ?? undefined;
  const error = params.get('error') ?? undefined;
  const errorDescription = params.get('error_description') ?? undefined;
  if (!code && !error) {
    return undefined;
  }
  return {
    code: code?.trim() || undefined,
    state: state?.trim() || undefined,
    error: error?.trim() || undefined,
    errorDescription: errorDescription?.trim() || undefined,
  };
}
