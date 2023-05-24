import { createRouter, createWebHashHistory, RouteRecordRaw,createWebHistory } from 'vue-router';
export const routes: RouteRecordRaw[] = [
  {
    path: '/',
    component: () => {
      return import('@/pages/listShow/ListShow.vue');
    },
  },{
    path: '/apiTokens',
    component: () => {
      return import('@/pages/apiTokens/ApiTokens.vue');
    },
  },
  // {
  //   path: '/login',
  //   component: () => {
  //     return import('@/pages/AppLogin.vue');
  //   },
  // },
];

export const router = createRouter({
  history: createWebHistory(),
  routes,
});




