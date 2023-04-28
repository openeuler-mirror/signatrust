<script setup lang="ts">
import { ref } from "vue";
import { Search } from "@element-plus/icons-vue";
import ChangeCheck from '@/components/ChangeCheck.vue'
const tableData = ref([
  {
    id: "1581943325545193472",
    certificationId: "E202210170000161",
    fullName: "Brother Tao",
    email: "jiangbaitao2@huawei.com",
    certificationCategory: "HCIA-openEuler",
    certifiedDate: 1654618000000,
    expiredDate: 1749225900000,
    validFlag: 1,
    certificationSource: "c8bc59ccd185402eb19eafb655201314",
    modifiedDate: null,
    modifiedBy: "sys",
    fullNameChinese: "韬哥",
    studentCountry: "193",
    cerCode: "c8bc59ccd185402eb19eafb655201314",
    examCode: null,
    certLanguage: null,
    sendEmail: 1,
    score: null,
    certPresentName: "OECA",
    cooperatorName: "人才市场",
    cooperatorId: "1565532827785592835"
  },
  {
    id: "1581943325545193472",
    certificationId: "E202210170000161",
    fullName: "Brother Tao",
    email: "jiangbaitao2@huawei.com",
    certificationCategory: "HCIA-openEuler",
    certifiedDate: 1654618000000,
    expiredDate: 1749225900000,
    validFlag: 1,
    certificationSource: "c8bc59ccd185402eb19eafb655201314",
    modifiedDate: null,
    modifiedBy: "sys",
    fullNameChinese: "韬哥",
    studentCountry: "193",
    cerCode: "c8bc59ccd185402eb19eafb655201314",
    examCode: null,
    certLanguage: null,
    sendEmail: 1,
    score: null,
    certPresentName: "OECA",
    cooperatorName: "人才市场",
    cooperatorId: "1565532827785592835"
  }
])
interface TableData {
  email: string; //电子邮箱
  fullNameChinese: string; //姓名
  cooperatorName: string; //考试单位
  cerCode: string; //证书编号
  certLevel: string; //认证等级
  score: string; //考试成绩
  certifiedDate: string; //授予日期
  id: string;
  certPresentName: string;
  certificationId: string;
}
const multipleTableRef = ref();
</script>

<template>
  <div class="main">
  <!-- <ChangeCheck/> -->
    <div class="search">
      <!-- <el-input
        v-model="searchInput"
        placeholder="请输入内容"
        :prefix-icon="Search"
        @change="querySearch"
        @clear="clearSearchInput"
      /> -->
      <el-input
        placeholder="请输入内容"
        :prefix-icon="Search"
      />
    </div>
    <el-table
      ref="multipleTableRef"
      :data="tableData"
      style="width: 100%"
    >
      <el-table-column label="Name" align="left" fixed>
        <template #default="scope">
          {{
            scope.row.fullNameChinese === null
              ? scope.row.fullName
              : scope.row.fullNameChinese
          }}</template
        >
      </el-table-column>
      <el-table-column prop="email" label="State" align="left" />
      <el-table-column prop="cooperatorName" label="Descirption" align="left" />
      <el-table-column prop="score" label="Operations" align="left" />

      <el-table-column prop="certPresentName" label="Key Type" align="left" />
      <el-table-column prop="certificationId" label="Create Time" align="left" />

      <el-table-column label="Expire Time" align="left" line-hight="0px">
        <template #default="scope">
         </template
        >
      </el-table-column>
      <el-table-column prop="certificationId" label="Create Time" align="left" width="150"  />
      <el-table-column prop="certificationId" label="Create Time" align="left" />
      <el-table-column prop="certificationId" label="Create Time" align="left" />
      <el-table-column prop="certificationId" label="Create Time" align="left" />
    </el-table>
  </div>
</template>

<style scoped lang="scss">
.main {
  padding: 42px 120px;
  position: relative;
  .search {
    margin-bottom: 24px;
    display: flex;
    .search-btn {
      width: 84px;
      margin-left: 24px;
      height: 32px;
      border: 1px solid #c3cedf;
      margin-top: 8px;
      cursor: pointer;
    }
  }
}

</style>
<style>
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
    background-color: #e5e8f0!important;
}
</style>