// 导入axios实例
import { AxiosRequestConfig } from 'axios';
import http from './request';
/**
 * 证书查询
 */

export const searchApi = (param: any) => http({
    method:'get',
    url:'/api-certification/console/certification/list',
    params:param
});
/**
 * 导出证书
 */

 export const exportApi = (param: any) => http({
    method:'get',
    url:'/api-certification/console/certification/list/certInfoExport',
    responseType:'blob',
    params:param
});



