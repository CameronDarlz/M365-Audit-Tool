import { IPublicClientApplication, AccountInfo } from '@azure/msal-browser';

const GRAPH_BASE = 'https://graph.microsoft.com/v1.0';
const GRAPH_BETA = 'https://graph.microsoft.com/beta';

async function getToken(instance: IPublicClientApplication, account: AccountInfo): Promise<string> {
  const response = await instance.acquireTokenSilent({
    scopes: ['https://graph.microsoft.com/.default'],
    account,
  });
  return response.accessToken;
}

export async function graphGet<T>(
  instance: IPublicClientApplication,
  account: AccountInfo,
  endpoint: string,
  beta = false,
): Promise<T> {
  const token = await getToken(instance, account);
  const base = beta ? GRAPH_BETA : GRAPH_BASE;
  const res = await fetch(`${base}${endpoint}`, {
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
    const res = await fetch(url, {
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
