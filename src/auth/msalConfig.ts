import { type Configuration, type PopupRequest } from '@azure/msal-browser';

export const msalConfig: Configuration = {
  auth: {
    clientId: import.meta.env.VITE_AZURE_CLIENT_ID || '',
    authority: 'https://login.microsoftonline.com/common',
    redirectUri: import.meta.env.VITE_AZURE_REDIRECT_URI || window.location.origin,
  },
  cache: {
    cacheLocation: 'sessionStorage',
  },
  system: {
    allowRedirectInIframe: false,
  },
};

export const loginRequest: PopupRequest = {
  scopes: [
    'User.Read',
    'User.Read.All',
    'Directory.Read.All',
    'Policy.Read.All',
    'Organization.Read.All',
    'Reports.Read.All',
    'SecurityEvents.Read.All',
    'AuditLog.Read.All',
    'IdentityRiskyUser.Read.All',
    'DeviceManagementManagedDevices.Read.All',
    'RoleManagement.Read.Directory',
    'Application.Read.All',
    'GroupMember.Read.All',
  ],
};

export const isConfigured = (): boolean => {
  return Boolean(import.meta.env.VITE_AZURE_CLIENT_ID);
};
