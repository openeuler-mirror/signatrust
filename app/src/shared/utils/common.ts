// 公共函数方法

import { requiredNumber } from "element-plus/es/components/table-v2/src/common";

/**
 * 方法pre=next视图不刷新
 * 解决数组直接赋值不刷新视图
 * @param pre 修改前的值
 * @param next 修改后数组
 */
export function commonAssignArray(pre: Array<any>, next: Array<any>) {
  pre.splice(0, pre.length);
  pre.push(...next);
}

/**
 * 计算除法返回商和余数
 * @param dividend 被除数
 * @param divisor 除数
 */
function computingDivision(dividend: number, divisor: number) {
  const quotient = Math.floor(dividend / divisor) || 0;
  const remainder = Math.round(dividend % divisor) || 0;
  return [quotient, remainder];
}

interface TimeRangeConfig {
  thousands: boolean;
}

/**
 * 将时间戳范围转换为时分秒天的展示方式
 * @param startTime 开始时间
 * @param endTime 结束时间
 */

export function timeRangeToRealTime(startTime: string | number, endTime: string | number, config?: TimeRangeConfig) {
  const { thousands = true } = config || {};
  const _rangeTime = Number(endTime) - Number(startTime);
  const rangeTime = thousands ? _rangeTime / 1000 : _rangeTime;
  const minutes = 60;
  const hours = 60 * minutes;
  const days = 24 * hours;
  // 返回时间值
  let s = 0;
  let min = 0;
  let h = 0;
  let day = 0;
  const calcDay = computingDivision(rangeTime, days);
  day = calcDay[0];
  s = calcDay[1];
  if (s) {
    const calcHour = computingDivision(s, hours);
    h = calcHour[0];
    s = calcHour[1];
  }
  if (s) {
    const calcMin = computingDivision(s, minutes);
    min = calcMin[0];
    s = calcMin[1];
  }
  let str = '';
  str += day ? `${day}days ` : '';
  str += h ? `${h}h ` : '';
  str += min ? `${min}min ` : '';
  str += s ? `${s}s ` : '';
  return {
    day,
    h,
    min,
    s,
    str: str ? str : '0s',
  };
}

export function dateFormat(time: any, type: string) {
  let formatTime;
  let date;
  if (time === 0) {
    date = new Date();
  } else {
    date = new Date(time);
  }
  let Year = date.getFullYear();
  let month = date.getMonth() + 1;
  let Month = month >= 10 ? month : '0' + month;
  let day = date.getDate();
  let Day = day >= 10 ? day : '0' + day;
  let Hour = date.getHours() < 10 ? '0' + date.getHours() : date.getHours();
  let Minute = date.getMinutes() < 10 ? '0' + date.getMinutes() : date.getMinutes();
  let Second = date.getSeconds() < 10 ? '0' + date.getSeconds() : date.getSeconds();
  if (type === 'yyyy-MM-dd') {
    formatTime = Year + '-' + Month + '-' + Day;
    return formatTime;
  } else if (type === 'yyyy-MM-dd hh:mm:ss') {
    formatTime = Year + '-' + month + '-' + day + ' ' + Hour + ':' + Minute + ':' + Second;
    return formatTime;
  } else if (type === 'hh:mm:ss') {
    formatTime = Hour + ':' + Minute + ':' + Second;
    return formatTime;
  } else {
    return 'error type!';
  }
}
/**
 * 判断数据是否为空
 * @param data 数据
 * @param strict 是否为严格模式
 * @returns boolean
 */
export function isCheckEmpty(data: any, strict = false): boolean {
  const strictArr = [null, undefined, '', NaN];
  if (strict) {
    return strictArr.includes(data);
  }
  return [...strictArr, 0, false].includes(data);
}

