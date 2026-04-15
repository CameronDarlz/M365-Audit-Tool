import { type IPublicClientApplication, type AccountInfo } from '@azure/msal-browser';
import { safeGraphGetAll } from '../graphClient';
import type { IdentityProtectionData, RiskyUser, RiskDetection } from '../../types/audit';

export async function collectIdentityProtection(
  instance: IPublicClientApplication,
  account: AccountInfo,
): Promise<IdentityProtectionData> {
  const [riskyUsersResult, detectionsResult] = await Promise.all([
    safeGraphGetAll<RiskyUser>(
      instance,
      account,
      "/identityProtection/riskyUsers?$filter=riskState eq 'atRisk'&$top=100",
    ),
    safeGraphGetAll<RiskDetection>(
      instance,
      account,
      '/identityProtection/riskDetections?$top=50&$orderby=detectedDateTime desc',
    ),
  ]);

  // Detect P2 limitation: if both error, mark as limited
  const hasError = Boolean(riskyUsersResult.error || detectionsResult.error);
  const limited = hasError && (
    riskyUsersResult.error?.includes('50000') ||
    riskyUsersResult.error?.includes('Authorization_RequestDenied') ||
    riskyUsersResult.error?.includes('Forbidden') ||
    detectionsResult.error?.includes('50000') ||
    detectionsResult.error?.includes('403') ||
    false
  );

  const error = riskyUsersResult.error || detectionsResult.error;

  return {
    riskyUsers: riskyUsersResult.data,
    riskDetections: detectionsResult.data,
    error: error ?? null,
    limited,
  };
}
