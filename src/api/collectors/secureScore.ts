import { IPublicClientApplication, AccountInfo } from '@azure/msal-browser';
import { safeGraphGetAll } from '../graphClient';
import { SecureScoreData, SecureScore } from '../../types/audit';

export async function collectSecureScore(
  instance: IPublicClientApplication,
  account: AccountInfo,
): Promise<SecureScoreData> {
  const { data, error } = await safeGraphGetAll<SecureScore>(
    instance,
    account,
    '/security/secureScores?$top=1',
  );
  return { secureScores: data, error };
}
