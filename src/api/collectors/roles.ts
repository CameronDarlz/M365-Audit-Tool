import { type IPublicClientApplication, type AccountInfo } from '@azure/msal-browser';
import { safeGraphGetAll } from '../graphClient';
import type { RolesData, RoleDefinition, RoleAssignment } from '../../types/audit';

export async function collectRoles(
  instance: IPublicClientApplication,
  account: AccountInfo,
): Promise<RolesData> {
  const [defsResult, assignmentsResult] = await Promise.all([
    safeGraphGetAll<RoleDefinition>(
      instance,
      account,
      '/roleManagement/directory/roleDefinitions?$filter=isBuiltIn eq true',
    ),
    safeGraphGetAll<RoleAssignment>(
      instance,
      account,
      '/roleManagement/directory/roleAssignments?$expand=principal',
    ),
  ]);

  const error = defsResult.error || assignmentsResult.error;

  return {
    roleDefinitions: defsResult.data,
    roleAssignments: assignmentsResult.data,
    error: error ?? null,
  };
}
