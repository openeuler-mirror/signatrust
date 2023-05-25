<script setup lang="ts">
import AppHeader from "@/components/AppHeader.vue";
import { useRoute, useRouter } from "vue-router";
import { getToken } from "@/api/show";
import { showGuard } from "@/shared/utils/login";
const router = useRouter();
const route = useRoute();
const queryToken = () => {
  getToken()
    .then(() => router.push("./"))
    .catch(() => showGuard());
};
queryToken()
</script>

<template>
  <header><app-header v-if="route.path !== '/login'"></app-header></header>
  <container>
    <router-view />
  </container>
</template>

<style lang="scss">
.login-iframe {
  width: 100%;
  height: 100vh;
}
#app {
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
}
.container {
  min-width: 1280px;
}
.wrap {
  max-width: 1416px;
  padding: 0 24px;
}
@media screen and (min-width: 1900px) {
  .wrap {
    margin: 0 auto;
  }
}
@media screen and (min-width: 1700px) and (max-width: 1900px) {
  .wrap {
    margin: 0 240px 0 auto;
  }
}
@media screen and (max-width: 1700px) {
  .wrap {
    margin: 0 auto;
  }
}
body {
  background: #f5f6f8;
}
</style>
