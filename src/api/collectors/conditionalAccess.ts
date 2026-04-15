import { type IPublicClientApplication, type AccountInfo } from '@azure/msal-browser';
import { safeGraphGetAll } from '../graphClient';
import type { ConditionalAccessData, ConditionalAccessPolicy, NamedLocation } from '../../types/audit';

export async function collectConditionalAccess(
  instance: IPublicClientApplication,
  account: AccountInfo,
): Promise<ConditionalAccessData> {
  const [policiesResult, locationsResult] = await Promise.all([
    safeGraphGetAll<ConditionalAccessPolicy>(
      instance,
      account,
      '/identity/conditionalAccessPolicies',
    ),
    safeGraphGetAll<NamedLocation>(
      instance,
      account,
      '/identity/conditionalAccess/namedLocations',
    ),
  ]);

  const error = policiesResult.error || locationsResult.error;

  return {
    policies: policiesResult.data,
    namedLocations: locationsResult.data,
    error: error ?? null,
  };
}
