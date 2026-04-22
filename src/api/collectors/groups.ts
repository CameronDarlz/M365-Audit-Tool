import { type IPublicClientApplication, type AccountInfo } from '@azure/msal-browser';
import { safeGraphGetAll } from '../graphClient';
import type { GroupsData, GroupLifecyclePolicy, Group, DirectorySetting } from '../../types/audit';

export async function collectGroups(
  instance: IPublicClientApplication,
  account: AccountInfo,
): Promise<GroupsData> {
  const [lifecycleResult, settingsResult, groupsResult] = await Promise.all([
    safeGraphGetAll<GroupLifecyclePolicy>(
      instance,
      account,
      '/groupLifecyclePolicies',
    ),
    safeGraphGetAll<DirectorySetting>(
      instance,
      account,
      '/settings',
    ),
    safeGraphGetAll<Group>(
      instance,
      account,
      "/groups?$filter=groupTypes/any(c:c eq 'Unified')&$select=id,displayName,visibility,resourceProvisioningOptions,groupTypes&$expand=owners($select=id,displayName)&$top=100",
    ),
  ]);

  const error = lifecycleResult.error || settingsResult.error || groupsResult.error;

  return {
    lifecyclePolicies: lifecycleResult.data,
    settings: settingsResult.data,
    groups: groupsResult.data,
    error: error ?? null,
  };
}
