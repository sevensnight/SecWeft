import { create } from 'zustand';

interface SessionState {
  accessToken: string | null;
  apiKey: string | null;
  displayName: string | null;
  expiresAt: number | null;
  projectId: string | null;
  clearOidcSession: () => void;
  clearApiKey: () => void;
  setOidcSession: (session: {
    accessToken: string;
    displayName: string;
    expiresAt: number | null;
  }) => void;
  setApiKey: (apiKey: string) => void;
  setProjectId: (projectId: string | null) => void;
}

// Deliberately memory-only: credentials must not enter localStorage, URLs or logs.
export const useSessionStore = create<SessionState>((set) => ({
  accessToken: null,
  apiKey: null,
  displayName: null,
  expiresAt: null,
  projectId: null,
  clearOidcSession: () => set({ accessToken: null, displayName: null, expiresAt: null, projectId: null }),
  clearApiKey: () => set({ apiKey: null }),
  setOidcSession: (session) => set(session),
  setApiKey: (apiKey) => set({ apiKey }),
  setProjectId: (projectId) => set({ projectId }),
}));
