// 导入axios实例
import http from './request';

// 换取token
export const getToken = () => http({
    method:'get',
    url:'/api/v1/users/info',

});

// 退出登录

export const queryIDToken = () => http({
    method:'post',
    url:'/api/v1/users/logout',


});

// 跳转
export const queryCourse = () => http({
    method:'get',
    url:'/api/v1/users/login',
});
// 详细信息
export const queryPermissions = (param:any) => http({
    method:'get',
    url:'/api/v1/users/',
    params:param

});
// 获取表格数据
export const queryAllData = (param:any) => http({
    method:'get',
    url:'/api/v1/keys/',
    params:param

});

//创建新的key
export const queryNewKey = (param:any) => http({
    method:'post',
    url:'/api/v1/keys/',
    data: param,

});
//注入key
export const queryImportKey = (param:any) => http({
    method:'post',
    url:'/api/v1/keys/import',
    data: param,

});
//删除key
export const queryDeleteKey = (param:any) => http({
    method:'post',
    url:`/api/v1/keys/${param}/cancel_delete`,


});
//无效化key
export const queryDisableKey = (param:any) => http({
    method:'post',
    url:`/api/v1/keys/${param}/disable`,

});
//激活key
export const queryEnableKey = (param:any) => http({
    method:'post',
    url:`/api/v1/keys/${param}/enable`,

});
//导出key
export const queryExportKey = (param:any) => http({
    method:'post',
    url:`/api/v1/keys/${param}/export`,


});
//请求删除key
export const queryRequestKey = (param:any) => http({
    method:'post',
    url:`/api/v1/keys/${param}/request_delete`,


});

//获取api_keys列表

export const queryApiKeys = () => http({
    method:'get',
    url:'/api/v1/users/api_keys',

});

// 删除api_keys

export const deleteApiKeys = (param:any) => http({
    method:'delete',
    url:`/api/v1/users/api_keys/${param}`,

});
//注册api_keys

export const getApiKeys = (param:any) => http({
    method:'post',
    url:'/api/v1/users/api_keys',
    data: param,
});

//姓名查重

export const headName = (param:any) => http({
    method:'head',
    url:'/api/v1/keys/name_identical',
    params: param,
});