import { createContext, useContext } from 'react';

export interface AuthActions {
  login: () => Promise<void>;
  logout: () => Promise<void>;
}

export const AuthContext = createContext<AuthActions | null>(null);

export function useAuthActions(): AuthActions {
  const value = useContext(AuthContext);
  if (!value) throw new Error('AuthBoundary is missing');
  return value;
}
