<script setup lang="ts">
import { ref, onMounted, reactive, watch } from "vue";
import { showGuard, logout, useStoreData, getUserAuth } from "@/shared/utils/login";
import { useRouter } from "vue-router";
import { useDataStore } from "@/store/data";
const useData = useDataStore();
const router = useRouter();
const isLogin = ref(false);
const dropdownCommand = (type: string) => {
  if (type === "logout") {
    isLogin.value = false;
  }
};
const toTokens = () => {
  router.push("/tokens");
};
const toHome = () => {
  router.push("/");
};
const toOpenEuler = () => {
  window.open("https://openeuler.org");
};
</script>
<template>
  <div class="common-content-bg-color common-level-one-color app-header">
    <div class="app-header-logo">
      <span @click="toHome" style="cursor: pointer">Signatrust</span>
      <img
        src="../assets/Black-horizontal.png"
        alt=""
        @click="toOpenEuler"
        class="title"
        style="cursor: pointer"
      />
    </div>
    <div class="app-header-opt">
      <div class="app-header-opt-control">
        <el-dropdown trigger="click" @command="dropdownCommand">
          <span class="construction-user-name">
            {{ useData.email }}
          </span>
          <template #dropdown>
            <el-dropdown-menu>
              <el-dropdown-item
                class="construction-quit"
                command="logout"
                @click="toTokens"
              >
                API tokens
              </el-dropdown-item>
              <el-dropdown-item
                class="construction-quit"
                command="logout"
                @click="logout"
              >
                Sign out
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
  background: #fff;
}
.app-header-logo {
  display: flex;
  align-items: center;
  margin-left: 120px;
  font-size: 20px;
  font-family: HuaweiSans-Bold, HuaweiSans;
  font-weight: 400;
  color: #000000;
  line-height: 24px;
  .title {
    margin-left: 8px;
    border-left: 1px solid #000000;
    padding-left: 12px;
  }
}
.app-header-opt {
  margin-right: 72px;
  display: flex;
  align-items: center;
  &-control {
    cursor: pointer;
    &:hover {
      color: #002fa7;
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
