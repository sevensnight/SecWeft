import { create } from 'zustand';

interface TaskViewState {
  filter: string;
  setFilter: (filter: string) => void;
}

export const useTaskViewStore = create<TaskViewState>((set) => ({
  filter: '',
  setFilter: (filter) => set({ filter }),
}));
