import { queryCourse, getToken, queryIDToken } from '@/api/show';
import { useCounter } from '@/store/counter';
import { storeToRefs } from 'pinia';
const LOGIN_KEYS = {
  USER_TOKEN: '_U_T_',
  USER_INFO: '_U_I_',
};

function setCookie(cname: string, cvalue: string, exdays: number) {
  const d = new Date();
  d.setTime(d.getTime() + exdays * 24 * 60 * 60 * 1000);
  const expires = `expires=${d.toUTCString()};path=/`;
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
  setCookie(cname, 'null', -1);
}

// 存储用户id及token，用于下次登录
export function saveUserAuth(code = '', photo = '') {
  if (!code) {
    deleteCookie(LOGIN_KEYS.USER_TOKEN);
    deleteCookie(LOGIN_KEYS.USER_INFO);
  } else {
    setCookie(LOGIN_KEYS.USER_TOKEN, code, 1);
    setCookie(LOGIN_KEYS.USER_INFO, photo, 1);
  }
}

// 获取用户id及token
export function getUserAuth() {
  const Authorization = getCookie(LOGIN_KEYS.USER_TOKEN) || '';
  const photo = getCookie(LOGIN_KEYS.USER_INFO) || '';
  if (!Authorization) {
    saveUserAuth();
  }
  return {
    Authorization,
    photo,
  };
}
const redirectUri = `${location.origin}/`;

// // 退出登录
export function logout() {
  queryIDToken().then((res: any) =>
    window.location.href = window.location.origin
  );
}

// 跳转首页
export function goToHome() {
  // window.location.href = window.location.origin;
  queryCourse().then(() => {});
}

export function getCodeByUrl() {
  const query = getUrlParam();
  if (query.code && query.state) {
    const param = {
      code: query.code,
    };
    getToken(param).then((res: any) => {
      saveUserAuth(res.data, res.data);
      deleteUrlCode(query);
      const newUrl = `${location.origin}/`;
      window.parent.window.location.href = newUrl;
    });
  }
}
// 删除url上的code
function deleteUrlCode(query: any) {
  const arr = Object.entries(query);
  let url = location.origin + location.pathname;
  if (arr.length > 2) {
    const _arr = arr.filter(item => !['code', 'state'].includes(item[0]));
    const search = _arr.reduce((pre, next) => {
      pre += `${next[0]}=${next[1]}`;
      return pre;
    }, '?');
    url += search;
  }
  history.replaceState(null, '', url);
}

function getUrlParam(url = window.location.search) {
  const param = {} as any;
  const arr = url.split('?');
  if (arr[1]) {
    const _arr = arr[1].split('&') || [];
    _arr.forEach((item: any) => {
      const it = item.split('=');
      if (it.length === 2) {
        const obj = {
          [it[0]]: it[1],
        };
        Object.assign(param, obj);
      }
    });
  }

  return param;
}

function createClient(community: string) {
  const obj: any = {
    client_id: '623c3c2f1eca5ad5fca6c58a',
    redirect_uri: 'http://127.0.0.1:5173',
    response_type: 'code',
    scope: 'openid profile',
  };
}
// scope配置，设置登录后用户返回信息
const scopeConfig = {
  scope: 'openid profile username',
};
export function showGuard() {
  // if (window.location.search.split('?')[1]) {
  // } else {
  //   window.location.assign(
  //     'https://omapi.osinfra.cn/oneid/oidc/authorize?client_id=623c3c2f1eca5ad5fca6c58a&redirect_uri=https://signatrust.test.osinfra.cn/api/v1/users/callback&scope=openid+profile+email&access_type=offline&response_type=code'
  //   )
  // }
  queryCourse();
}

// token失效跳转首页
export function tokenFailIndicateLogin() {
  saveUserAuth();
  const { guardAuthClient } = useStoreData();
  guardAuthClient.value = {};
  // goToHome();
}

/**
 * @callback store 将store返回，使用解构赋值接受
 */
export function useStoreData() {
  const counter = useCounter();
  const stores = storeToRefs(counter);
  return stores;
}

// export function hasPermission(per: string) {
//   const { guardAuthClient } = useStoreData();
//   if (Array.isArray(guardAuthClient?.value?.permissions)) {
//     return guardAuthClient.value.permissions.includes(per);
//   }
//   return false;
// }
