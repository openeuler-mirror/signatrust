<template>
  <!-- <iframe :src="loginIframeSrc" class="login-iframe" frameborder="0"></iframe> -->
  <!-- <OButton class="login-btn" type="primary" animation @click="showGuard()"
      >前往登录
    </OButton> -->
</template>

<script setup lang="ts">
import { reactive, ref, onBeforeMount, onMounted } from "vue";
import { useStoreData } from "@/shared/utils/login";
import { showGuard, getUserAuth } from "@/shared/utils/login";
showGuard()
</script>
<style scoped lang="scss">
.login-iframe {
  width: 100%;
  height: 100vh;
}
</style>
