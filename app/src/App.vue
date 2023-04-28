<script setup lang="ts">
import AppFooter from "@/components/AppFooter.vue";
import AppHeader from '@/components/AppHeader.vue'
</script>

<template>
  <header><app-header></app-header></header>
  <div>
    <router-view />
  </div>
  <footer><app-footer></app-footer></footer>
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
  background: #fff;
}
footer {
  background: #060612;
  position: absolute;
  bottom: 0;
  width: 100%;
}
</style>
