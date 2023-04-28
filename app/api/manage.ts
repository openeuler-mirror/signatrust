// 导入axios实例
import { AxiosRequestConfig } from 'axios';
import http from './request';

// 第三方认证管理查询
export const queryCooperator = (param: any) =>
  http({
    method: 'get',
    url: '/api-certification/console/cooperator/list',
    params: param,
  });
// 第三方新增管理查询
export const queryCertcategory = (param: any) =>
  http({
    method: 'get',
    url: '/api-certification/console/cooperator/certCategory/list',
    params: param,
  });

// 查询证书类型
export const queryCertTypeList = () =>
  http({
    method: 'get',
    url: '/api-certification/console/certType/list',
    // params:param
  });

// 新增证书
export const queryCooperatorSave = (param: any) =>
  http({
    method: 'post',
    url: '/api-certification/console/cooperator/save',
    data: param,
  });
// 删除证书
export const queryCooperatorDelete = (param: any) =>
  http({
    method: 'post',
    url: '/api-certification/console/cooperator/delete',
    params: param,
  });
// 证书详情
export const queryCooperatorDetail = (param: any) =>
  http({
    method: 'get',
    url: '/api-certification/console/cooperator/detail',
    params: param,
  });
// 上传LOGO
export const queryConsoleFileUpload = (param: any) =>
  http({
    method: 'post',
    url: '/api-certification/console/fileUpload?type=LOGO',
    data: param,
  });
