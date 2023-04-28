<template>
  <div class='mainc' ><div class='mainc-sp' v-for="(item,index) in check" :key='item'><span>{{item}}</span></div></div>
</template>
<script setup lang='ts'>
const check = ['a','b','c','d']
</script>
<style scoped lang='scss'>
.mainc{
  display:flex;
  position:relative;
  margin-bottom:50px;
&-sp{
  position:absolute; 
  right:20px;
  height:40px;
  border: 1px solid red;
  margin-left:10px;
}
}
</style>