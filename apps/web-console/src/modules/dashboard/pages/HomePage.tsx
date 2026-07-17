import { authMode } from '../../../auth/config';
import { EnterpriseAccessPage } from '../../identity/pages/EnterpriseAccessPage';
import { DashboardPage } from './DashboardPage';

export function HomePage() {
  return authMode === 'oidc' ? <EnterpriseAccessPage /> : <DashboardPage />;
}
