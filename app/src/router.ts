import {
  createRouter,
  createWebHashHistory,
  RouteRecordRaw,
  createWebHistory,
} from 'vue-router';
import ApiTokens from '@/pages/apiTokens/ApiTokens.vue';
export const routes: RouteRecordRaw[] = [
  {
    path: '/',
    component: () => {
      return import('@/pages/listShow/ListShow.vue');
    },
  },
  {
    path: '/tokens',
    component: ApiTokens,
  },
];

export const router = createRouter({
  history: createWebHistory(),
  routes,
});
