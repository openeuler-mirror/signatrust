<template>
  <div class="container">
    <div class="title">State and Permissions</div>
    <el-table :data="tableData" style="width: 50%">
      <el-table-column prop="state" label="State/permission" width="180" />
      <el-table-column prop="sign" label="Sign" width="180" />
      <el-table-column prop="display" label="Display" />
      <el-table-column prop="keys" label="Export Keys" />
      <el-table-column prop="note" label="Note" width="300" />
    </el-table>
  </div>
</template>

<script lang="ts" setup>
const tableData = [
  {
    state: "Disabled",
    sign: "NOK",
    display: "OK",
    keys:'OK',
    note:'default state when key created Pending'
  },
  {
    state: "Enabled",
    sign: "OK",
    display: "OK",
    keys:'OK',
    note:'single administratr is permitted'
  },
  {
    state: "Panding Delete",
    sign: "NOK",
    display: "OK",
    keys:'OK',
    note:'enabled key requires multiple administrators to delete（>=3）'
  },
  {
    state: "Deleted",
    sign: "NOK",
    display: "NOK",
    keys:'NOK',
    note:''
  },
 
];
</script>
<style scoped lang="scss">
.container {
  margin-top: 100px;
  margin-bottom: 100px;
  .title {
    font-size: 18px;
    font-family: PingFangSC-Regular, PingFang SC;
    font-weight: 400;
    color: #000000;
    line-height: 26px;
    margin-bottom: 16px;
  }
}
</style>
<style lang="scss">
.container {
  .el-table th {
    background-color: #fff !important;
  }
  .el-table--border .el-table__cell {
    border-right: none !important;
  }
  .el-table {
    --el-table-row-hover-bg-color: #fff;
    --el-table-border: 1px solid #000;
    --el-table-header-text-color:#000;
    --el-text-color-secondary:#555;
    border: 1px solid #000;
  }
}
</style>
