import { defineStore } from 'pinia';
export const useBaseStore = defineStore('base', {
  state: () => ({
    dialogVisible: false,
    dialogTwoVisible: false,
    copyValue: '',
  }),
  actions: {},
  getters: {},
});
