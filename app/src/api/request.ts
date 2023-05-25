import axios from 'axios';
import type { AxiosRequestConfig, AxiosPromise } from 'axios';
import { ElMessage } from 'element-plus';
import { baseUrls } from './baseUrl';
import { getUserAuth, tokenFailIndicateLogin,showGuard } from '@/shared/utils/login';

// 创建一个 axios 实例
const service = axios.create({
  // baseURL: baseUrls, // 所有的请求地址前缀部分
  timeout: 60000, // 请求超时时间毫秒
  headers: {
    // 设置后端需要的传参类型
  },
});
// 添加请求拦截器
service.interceptors.request.use(
  // 在发送请求之前做些什么

  (config: any) => {
    // const { Authorization} = getUserAuth();
    // const Authorization = 'LzPvbFaBQO45oqoXv8m31I2g0eO5WvkF67k7J515'
    //   if (Authorization) {
    //     const to = {
    //       Authorization,
    //     };
    //     Object.assign(config.headers, to);
    //   }
    return config;
  },
  error => {
    // 对请求错误做些什么
    console.log(error);
    return Promise.reject(error);
  }
);

// 添加响应拦截器
service.interceptors.response.use(
  response => {
    // 2xx 范围内的状态码都会触发该函数。
    // 对响应数据做点什么
    const dataAxios = response.data;
    // 这个状态码是和后端约定的
    const code = dataAxios.reset;
    return dataAxios;
  },
  error => {
    // 超出 2xx 范围的状态码都会触发该函数。
    // 对响应错误做点什么
    if (error.response.status === 401) {
      // ElMessage.error('Please log in again');
      // tokenFailIndicateLogin();
      showGuard();
    }
    if (error.response.status === 403) {
      // router.replace({path:'/'});
      // useUserStore.state.dialogFormVisible = true;
    }
    console.log(error);
    return Promise.reject(error);
  }
);

export default function (
  urlParam: string | AxiosRequestConfig,
  param?: AxiosRequestConfig
): AxiosPromise {
  if (typeof urlParam === 'string') {
    return service(urlParam, param);
  }
  return service(urlParam);
}
