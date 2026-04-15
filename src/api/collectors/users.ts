import { type IPublicClientApplication, type AccountInfo } from '@azure/msal-browser';
import { safeGraphGetAll } from '../graphClient';
import type { UsersData, User } from '../../types/audit';

export async function collectUsers(
  instance: IPublicClientApplication,
  account: AccountInfo,
): Promise<UsersData> {
  const { data, error } = await safeGraphGetAll<User>(
    instance,
    account,
    '/users?$select=id,displayName,userPrincipalName,accountEnabled,assignedLicenses,signInActivity,userType,passwordPolicies,createdDateTime&$top=999',
  );
  return { users: data, error };
}
