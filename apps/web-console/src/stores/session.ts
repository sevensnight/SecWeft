import { create } from 'zustand';

interface SessionState {
  apiKey: string | null;
  clearApiKey: () => void;
  setApiKey: (apiKey: string) => void;
}

// Deliberately memory-only: credentials must not enter localStorage, URLs or logs.
export const useSessionStore = create<SessionState>((set) => ({
  apiKey: null,
  clearApiKey: () => set({ apiKey: null }),
  setApiKey: (apiKey) => set({ apiKey }),
}));
