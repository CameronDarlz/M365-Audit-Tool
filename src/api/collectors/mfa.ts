import { IPublicClientApplication, AccountInfo } from '@azure/msal-browser';
import { safeGraphGetAll, safeGraphGet } from '../graphClient';
import { MfaData, UserRegistrationDetail, AuthMethodsPolicy } from '../../types/audit';

export async function collectMfa(
  instance: IPublicClientApplication,
  account: AccountInfo,
): Promise<MfaData> {
  const [regResult, policyResult] = await Promise.all([
    safeGraphGetAll<UserRegistrationDetail>(
      instance,
      account,
      '/reports/authenticationMethods/userRegistrationDetails?$top=999',
    ),
    safeGraphGet<AuthMethodsPolicy>(
      instance,
      account,
      '/policies/authenticationMethodsPolicy',
    ),
  ]);

  const error = regResult.error || policyResult.error;

  return {
    registrationDetails: regResult.data,
    authMethodsPolicy: policyResult.data,
    error: error ?? null,
  };
}
