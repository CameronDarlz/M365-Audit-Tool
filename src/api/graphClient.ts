import { type IPublicClientApplication, type AccountInfo, InteractionRequiredAuthError } from '@azure/msal-browser';

const GRAPH_BASE = 'https://graph.microsoft.com/v1.0';
const GRAPH_BETA = 'https://graph.microsoft.com/beta';

const TOKEN_REQUEST = { scopes: ['https://graph.microsoft.com/.default'] };

// Each individual HTTP request times out after this many ms.
// Prevents a single slow Graph endpoint from hanging the entire audit.
const REQUEST_TIMEOUT_MS = 30_000;

async function getToken(instance: IPublicClientApplication, account: AccountInfo): Promise<string> {
  try {
    const response = await instance.acquireTokenSilent({ ...TOKEN_REQUEST, account });
    return response.accessToken;
  } catch (e) {
    if (e instanceof InteractionRequiredAuthError) {
      await instance.acquireTokenRedirect({ ...TOKEN_REQUEST, account });
      throw new Error('Redirecting for re-authentication…');
    }
    throw e;
  }
}

async function fetchWithTimeout(url: string, init: RequestInit): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    return await fetch(url, { ...init, signal: controller.signal });
  } catch (e) {
    if ((e as Error).name === 'AbortError') {
      throw new Error(`Request timed out after ${REQUEST_TIMEOUT_MS / 1000}s: ${url}`);
    }
    throw e;
  } finally {
    clearTimeout(timer);
  }
}

export async function graphGet<T>(
  instance: IPublicClientApplication,
  account: AccountInfo,
  endpoint: string,
  beta = false,
): Promise<T> {
  const token = await getToken(instance, account);
  const base = beta ? GRAPH_BETA : GRAPH_BASE;
  const res = await fetchWithTimeout(`${base}${endpoint}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({})) as { error?: { message?: string; code?: string } };
    const msg = err?.error?.message ?? res.statusText;
    const code = err?.error?.code ?? String(res.status);
    throw Object.assign(new Error(`Graph ${res.status} on ${endpoint}: ${msg}`), { code, status: res.status });
  }
  return res.json() as Promise<T>;
}

export async function graphGetAll<T>(
  instance: IPublicClientApplication,
  account: AccountInfo,
  endpoint: string,
  beta = false,
): Promise<T[]> {
  const base = beta ? GRAPH_BETA : GRAPH_BASE;
  let results: T[] = [];
  let url: string | null = `${base}${endpoint}`;
  while (url) {
    const token = await getToken(instance, account);
    const res = await fetchWithTimeout(url, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({})) as { error?: { message?: string; code?: string } };
      const msg = err?.error?.message ?? res.statusText;
      const code = err?.error?.code ?? String(res.status);
      throw Object.assign(new Error(`Graph ${res.status} on ${endpoint}: ${msg}`), { code, status: res.status });
    }
    const data = await res.json() as { value?: T[]; '@odata.nextLink'?: string };
    results = results.concat(data.value ?? []);
    url = data['@odata.nextLink'] ?? null;
  }
  return results;
}

export async function safeGraphGet<T>(
  instance: IPublicClientApplication,
  account: AccountInfo,
  endpoint: string,
  beta = false,
): Promise<{ data: T | null; error: string | null }> {
  try {
    const data = await graphGet<T>(instance, account, endpoint, beta);
    return { data, error: null };
  } catch (e) {
    return { data: null, error: (e as Error).message };
  }
}

export async function safeGraphGetAll<T>(
  instance: IPublicClientApplication,
  account: AccountInfo,
  endpoint: string,
  beta = false,
): Promise<{ data: T[]; error: string | null }> {
  try {
    const data = await graphGetAll<T>(instance, account, endpoint, beta);
    return { data, error: null };
  } catch (e) {
    return { data: [], error: (e as Error).message };
  }
}
