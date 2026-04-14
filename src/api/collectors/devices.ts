import { IPublicClientApplication, AccountInfo } from '@azure/msal-browser';
import { safeGraphGetAll } from '../graphClient';
import { DevicesData, ManagedDevice, DeviceCompliancePolicy } from '../../types/audit';

export async function collectDevices(
  instance: IPublicClientApplication,
  account: AccountInfo,
): Promise<DevicesData> {
  const [devicesResult, policiesResult] = await Promise.all([
    safeGraphGetAll<ManagedDevice>(
      instance,
      account,
      '/deviceManagement/managedDevices?$select=id,deviceName,operatingSystem,osVersion,complianceState,lastSyncDateTime,managedDeviceOwnerType,enrolledDateTime&$top=999',
    ),
    safeGraphGetAll<DeviceCompliancePolicy>(
      instance,
      account,
      '/deviceManagement/deviceCompliancePolicies',
    ),
  ]);

  const error = devicesResult.error || policiesResult.error;

  return {
    managedDevices: devicesResult.data,
    compliancePolicies: policiesResult.data,
    error: error ?? null,
  };
}
