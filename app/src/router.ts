import { createRouter, createWebHashHistory, RouteRecordRaw,createWebHistory } from 'vue-router';
export const routes: RouteRecordRaw[] = [
  {
    path: '/',
    component: () => {
      return import('@/pages/listShow/ListShow.vue');
    },
  },
];

export const router = createRouter({
  history: createWebHistory(),
  routes,
});




