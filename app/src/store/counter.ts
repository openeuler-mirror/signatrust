import { defineStore } from 'pinia';
import { ref } from 'vue';

export const useCounter = defineStore('counter', () => {
  // 登录信息
  const guardAuthClient = ref({} as any);
  const isLoggingIn = ref(false);
  const loginIframeSrc = ref();
  const dialogImageUrl = ref()
  return { guardAuthClient, isLoggingIn, loginIframeSrc ,dialogImageUrl };
});
