import axios from 'axios';
import type { AxiosRequestConfig, AxiosPromise } from 'axios';
import { ElMessage } from 'element-plus';
import { showGuard } from '@/shared/utils/login';
import Cookies from 'js-cookie';
// 创建一个 axios 实例
const service = axios.create({
  timeout: 60000, // 请求超时时间毫秒
  headers: {
    // 设置后端需要的传参类型
  },
});
// 添加请求拦截器
service.interceptors.request.use(
  (config) => {
    // 在发送请求之前做些什么
    const token = Cookies.get('Xsrf-Token');
    if (token) {
      config.headers['Xsrf-Token'] = token;
    }
    return config;
  },
  (error) => {
    // 对请求错误做些什么
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
      showGuard();
    }
    if (error.response.status === 500) {
      ElMessage.error('Server error');
    }
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
