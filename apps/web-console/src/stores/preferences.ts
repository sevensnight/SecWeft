import { create } from 'zustand';
import { persist } from 'zustand/middleware';

export type ColorMode = 'dark' | 'light';
export type AppLocale = 'en-US' | 'zh-CN';

interface PreferencesState {
  colorMode: ColorMode;
  locale: AppLocale;
  setColorMode: (mode: ColorMode) => void;
  setLocale: (locale: AppLocale) => void;
}

export const usePreferencesStore = create<PreferencesState>()(
  persist(
    (set) => ({
      colorMode: 'light',
      locale: 'zh-CN',
      setColorMode: (colorMode) => set({ colorMode }),
      setLocale: (locale) => set({ locale }),
    }),
    {
      name: 'vulnlab-ui-preferences',
      partialize: ({ colorMode, locale }) => ({ colorMode, locale }),
    },
  ),
);
