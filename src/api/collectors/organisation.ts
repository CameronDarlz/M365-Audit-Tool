import { type IPublicClientApplication, type AccountInfo } from '@azure/msal-browser';
import { safeGraphGet } from '../graphClient';
import type { OrgData, Organization } from '../../types/audit';

interface OrgListResponse {
  value: Organization[];
}

export async function collectOrganisation(
  instance: IPublicClientApplication,
  account: AccountInfo,
): Promise<OrgData> {
  const { data, error } = await safeGraphGet<OrgListResponse>(
    instance,
    account,
    '/organization?$select=id,displayName,countryLetterCode,verifiedDomains,createdDateTime,tenantType',
  );
  return {
    organization: data?.value?.[0] ?? null,
    error,
  };
}
