<script setup lang="ts">
import {
    ref, onMounted ,reactive, watch
} from 'vue';

import { useRouter } from 'vue-router';
const router = useRouter();
  const isLogin = ref(false);
  const name = ref('Admin');
  const dropdownCommand = (type: string) => {
    if (type === 'logout') {
        isLogin.value = false;
    }
};
</script>
<template>
  <div class="common-content-bg-color common-level-one-color app-header">
    <div class="app-header-logo">
         <div class="title">

         </div>
         Signature | OpenEuler
    </div>
    <div class="app-header-opt">

      <div class="app-header-opt-control">
        <el-dropdown trigger="click" @command="dropdownCommand">
          <span class="construction-user-name">
            {{ name }}

          </span>
          <template #dropdown>
            <el-dropdown-menu>
              <el-dropdown-item class="construction-quit" command="logout">
                退出
              </el-dropdown-item>
            </el-dropdown-menu>
          </template>
        </el-dropdown>

      </div>
      </div>

  </div>
</template>
<style scoped lang="scss">
.app-header {
  display: flex;
  height: 80px;
  align-items: center;
  justify-content: space-between;
  box-shadow: 0px 20px 70px 0px rgba(0, 0, 0, 0.25);
}
.app-header-logo {
  height: 80px;
  display: flex;
  align-items: center;
  margin-left: 40px;
  font-size: 18px;
font-family: PingFangSC-Regular, PingFang SC;
font-weight: 400;
color: #000000;
line-height: 26px;
  .title{
    width: 30px;
    height: 34px;
    margin-right: 12px;
    // background-image: url('../assets/openEuler／logo／new.png');

  }
}
.app-header-opt {
  margin-right: 72px;
  display: flex;
  align-items: center;
  &-control {
    cursor: pointer;
    &:hover {
      color: #002FA7;
    }
  }
  &-git {
    margin: 0 40px;
  }
}
.logo {
  height: 60px;
  width: 400px;
  margin-top: 10px;
  cursor: pointer;
}
.img {
  width: 30px;
  height: 30px;
  border-radius: 50%;
  cursor: pointer;
}
</style>
