<script setup lang="ts">
import { ref } from "vue";
import ChangeCheck from "./ChangeCheck.vue";
import Permissions from "@/components/Permissions.vue";
import AppFooter from "@/components/AppFooter.vue";
import PrivateTable from "./PrivateTable.vue";
import PublicTable from "./PublicTable.vue";
</script>

<template>
  <div class="main">
    <ChangeCheck />
    <PublicTable/>
    <PrivateTable/>
    <Permissions />

    
  </div>
  <footer>
    <app-footer></app-footer>
  </footer>
</template>

<style scoped lang="scss">
.main {
  padding: 42px 120px;
  position: relative;
}
</style>
<style lang="scss">
.demo-pagination-block {
  --el-component-size: 32px;
}
.el-select-dropdown__item {
  padding: 0 20px 0 30px;
}
/* 去掉全选按钮 */
.el-table .disabledCheck .cell .el-checkbox__inner {
  display: none !important;
}
.el-table th {
  background-color: #e5e8f0 !important;
}
</style>
