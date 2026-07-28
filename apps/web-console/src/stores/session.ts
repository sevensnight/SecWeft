import { create } from 'zustand';

const API_KEY_SESSION_STORAGE_KEY = 'vulnlab.compatibility.apiKey';

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

function safeSessionStorage(): Storage | null {
  if (typeof window === 'undefined') return null;
  try {
    return window.sessionStorage;
  } catch {
    return null;
  }
}

function readStoredApiKey(): string | null {
  const value = safeSessionStorage()?.getItem(API_KEY_SESSION_STORAGE_KEY);
  return value && value.length > 0 ? value : null;
}

function storeApiKey(apiKey: string) {
  safeSessionStorage()?.setItem(API_KEY_SESSION_STORAGE_KEY, apiKey);
}

function removeStoredApiKey() {
  safeSessionStorage()?.removeItem(API_KEY_SESSION_STORAGE_KEY);
}

// API keys are kept only for the current browser tab session: refresh-safe, but not
// persisted to localStorage, URLs or logs.
export const useSessionStore = create<SessionState>((set) => ({
  accessToken: null,
  apiKey: readStoredApiKey(),
  displayName: null,
  expiresAt: null,
  projectId: null,
  clearOidcSession: () => set({ accessToken: null, displayName: null, expiresAt: null, projectId: null }),
  clearApiKey: () => {
    removeStoredApiKey();
    set({ apiKey: null });
  },
  setOidcSession: (session) => set(session),
  setApiKey: (apiKey) => {
    storeApiKey(apiKey);
    set({ apiKey });
  },
  setProjectId: (projectId) => set({ projectId }),
}));
