import { PublicClientApplication } from '@azure/msal-browser';
import {
  MsalProvider,
  AuthenticatedTemplate,
  UnauthenticatedTemplate,
  useMsal,
} from '@azure/msal-react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { msalConfig, isConfigured } from './auth/msalConfig';
import { SetupGuide } from './components/setup/SetupGuide';
import { LoginPage } from './pages/LoginPage';
import { DashboardPage } from './pages/DashboardPage';

const msalInstance = new PublicClientApplication(msalConfig);

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: false,
      refetchOnWindowFocus: false,
    },
  },
});

function AuthRouter() {
  const { accounts } = useMsal();
  const account = accounts[0] ?? null;

  return (
    <>
      <AuthenticatedTemplate>
        {account ? <DashboardPage account={account} /> : null}
      </AuthenticatedTemplate>
      <UnauthenticatedTemplate>
        <LoginPage />
      </UnauthenticatedTemplate>
    </>
  );
}

export default function App() {
  if (!isConfigured()) {
    return <SetupGuide />;
  }

  return (
    <MsalProvider instance={msalInstance}>
      <QueryClientProvider client={queryClient}>
        <AuthRouter />
      </QueryClientProvider>
    </MsalProvider>
  );
}
