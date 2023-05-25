import {  queryIDToken } from '@/api/show';
import { useCounter } from '@/store/counter';
import { storeToRefs } from 'pinia';
const LOGIN_KEYS = {
  USER_TOKEN: 'Signatrust',
};

function setCookie(cname: string, cvalue: string, isDelete?: boolean) {
  const deleteStr = isDelete ? 'max-age=0; ' : '';
  const domain = import.meta.env.VITE_COOKIE_DOMAIN;
  const expires = `${deleteStr}path=/; domain=${domain}`;
  document.cookie = `${cname}=${cvalue}; ${expires}`;
}
function getCookie(cname: string) {
  const name = `${cname}=`;
  const ca = document.cookie.split(';');
  for (let i = 0; i < ca.length; i++) {
    const c = ca[i].trim();
    if (c.indexOf(name) === 0) {
      return c.substring(name.length, c.length);
    }
  }
  return '';
}
function deleteCookie(cname: string) {
  setCookie(cname, 'null', true);
}

// 存储用户id及token，用于下次登录
export function saveUserAuth(code = '') {
  if (!code) {
    deleteCookie(LOGIN_KEYS.USER_TOKEN);
  } else {
    setCookie(LOGIN_KEYS.USER_TOKEN, code);
  }
}

// 获取用户id及token
export function getUserAuth() {
  const token = getCookie(LOGIN_KEYS.USER_TOKEN) || '';
  if (!token) {
    saveUserAuth();
  }
  return {
    token,
  };
}


// 退出登录
export function logout() {
  queryIDToken().then((res: any) =>window.location.href='https://openeuler-usercenter.test.osinfra.cn/logout?redirect_uri=https://signatrust.test.osinfra.cn/api/v1/users/login'
 
  );
}

export function showGuard() {
  window.location.href = 'https://signatrust.test.osinfra.cn/api/v1/users/login'
}

// token失效跳转首页
export function tokenFailIndicateLogin() {
  saveUserAuth();
  const { guardAuthClient } = useStoreData();
  guardAuthClient.value = {};
}

/**
 * @callback store 将store返回，使用解构赋值接受
 */
export function useStoreData() {
  const counter = useCounter();
  const stores = storeToRefs(counter);
  return stores;
}

