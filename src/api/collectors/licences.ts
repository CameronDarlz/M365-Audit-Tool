import { type IPublicClientApplication, type AccountInfo } from '@azure/msal-browser';
import { safeGraphGetAll } from '../graphClient';
import type { LicencesData, SubscribedSku } from '../../types/audit';

export async function collectLicences(
  instance: IPublicClientApplication,
  account: AccountInfo,
): Promise<LicencesData> {
  const { data, error } = await safeGraphGetAll<SubscribedSku>(
    instance,
    account,
    '/subscribedSkus',
  );
  return { subscribedSkus: data, error };
}
