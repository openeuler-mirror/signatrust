// 导入axios实例
import http from './request';

// 证书类型统计
export const typeStatistics = () => http({
    method:'get',
    url:'/api-certification/console/certification/statistics/countByCooperator',

});
// 证书增长分布
export const growStatistics = (param:any) => http({
    method:'get',
    url:'/api-certification/console/certification/statistics/countByIncrease',
    params:param

});

// 换取token
export const getToken = (param:any) => http({
    method:'get',
    url:'/api-certification/console/auth/login',
    params:param

});

// 退出登录

export const queryIDToken = () => http({
    method:'get',
    url:'/api-certification/console/auth/logout',


});