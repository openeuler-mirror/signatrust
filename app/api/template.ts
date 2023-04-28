// 导入axios实例
import { AxiosRequestConfig } from 'axios';
import http from './request';

/**
 * 证书编辑
 */

 export const editApi = (param: any) => http({
    method:'put',
    url:'/api-certification/console/certification',
    params:param
});


/**
 * 信息上传
 */

 export const uploadApi = (param: any) => http({
    method:'put',
    url:'/api-certification/console/certification',
    params:param
});

/**
 * 证书删除
 */

 export const deleteApi = (param: any) => http({
    method:'delete',
    url:'/api-certification/console/certification',
    params:param
});