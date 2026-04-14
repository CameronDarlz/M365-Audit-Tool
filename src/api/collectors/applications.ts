import { IPublicClientApplication, AccountInfo } from '@azure/msal-browser';
import { safeGraphGetAll } from '../graphClient';
import { ApplicationsData, AppRegistration, ServicePrincipal } from '../../types/audit';

export async function collectApplications(
  instance: IPublicClientApplication,
  account: AccountInfo,
): Promise<ApplicationsData> {
  const [appsResult, spResult] = await Promise.all([
    safeGraphGetAll<AppRegistration>(
      instance,
      account,
      '/applications?$select=id,displayName,appId,createdDateTime,owners,passwordCredentials,keyCredentials,requiredResourceAccess&$top=999',
    ),
    safeGraphGetAll<ServicePrincipal>(
      instance,
      account,
      "/servicePrincipals?$filter=tags/any(t:t eq 'WindowsAzureActiveDirectoryIntegratedApp')&$select=id,displayName,appId,appOwnerOrganizationId,publisherName,permissionScopes,tags&$top=200",
    ),
  ]);

  const error = appsResult.error || spResult.error;

  return {
    appRegistrations: appsResult.data,
    servicePrincipals: spResult.data,
    error: error ?? null,
  };
}
