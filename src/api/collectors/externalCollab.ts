import { IPublicClientApplication, AccountInfo } from '@azure/msal-browser';
import { safeGraphGet } from '../graphClient';
import { ExternalCollabData, ExternalIdentitiesPolicy, AuthorizationPolicy } from '../../types/audit';

export async function collectExternalCollab(
  instance: IPublicClientApplication,
  account: AccountInfo,
): Promise<ExternalCollabData> {
  const [extResult, authResult] = await Promise.all([
    safeGraphGet<ExternalIdentitiesPolicy>(
      instance,
      account,
      '/policies/externalIdentitiesPolicy',
    ),
    safeGraphGet<AuthorizationPolicy>(
      instance,
      account,
      '/policies/authorizationPolicy',
    ),
  ]);

  const error = extResult.error || authResult.error;

  return {
    externalIdentitiesPolicy: extResult.data,
    authorizationPolicy: authResult.data,
    error: error ?? null,
  };
}
