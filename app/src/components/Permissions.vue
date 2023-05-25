<template>
  <div class="container">
    <div class="title">State and Permissions</div>
    <el-table :data="tableData" style="width: 50%">
      <el-table-column prop="state" label="State/Permission" width="120" />
      <el-table-column prop="sign" label="Sign" width="100" />
      <el-table-column prop="display" label="Display" width="100" />
      <el-table-column prop="keys" label="Export Public Keys" width="100" />
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
    note:'Default state when key created'
  },
  {
    state: "Enabled",
    sign: "OK",
    display: "OK",
    keys:'OK',
    note:'Public key can be enabled by any administrator, while private key can be enabled by the creator'
  },
  {
    state: "Pending Delete",
    sign: "NOK",
    display: "OK",
    keys:'OK',
    note:'Public Key requires multiple administrators to request deleting（>=3), while private key can be deleted by the creator directly'
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
