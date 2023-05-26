<template>
  <div class="main">
    <el-breadcrumb :separator-icon="ArrowRight">
      <el-breadcrumb-item :to="{ path: '/' }">Signatrust</el-breadcrumb-item>
      <el-breadcrumb-item>API tokens</el-breadcrumb-item>
    </el-breadcrumb>
    <div class="btn" @click="showTokens">Generate new token</div>
    <div class="table">
      <div class="title">Personal Tokens</div>
      <div class="table-th" v-for="(item, index) in tableData" :key="index">
        <div class="th">
          <div class="th-title">
            {{ item.description }}
            <div class="small">
              {{ item.create_at.substring(0, 10) }}, {{ item.expire_at.substring(0, 10) }}
            </div>
          </div>
          <div class="th-btn">
            <el-button @click="openDialog(item.id)">Delete</el-button>
          </div>
        </div>
      </div>
      <el-dialog v-model="centerDialogVisible" title="Confirmation" width="30%" center>
        <span class="textCenter"> Confirm to delete  </span>
        <template #footer>
          <span class="dialog-footer">
            <el-button @click="centerDialogVisible = false">Cancel</el-button>
            <el-button type="primary" @click="deletKeys()"> Confirm </el-button>
          </span>
        </template>
      </el-dialog>
    </div>
  </div>
  <footer>
    <app-footer></app-footer>
  </footer>
  <el-dialog
    v-model="useBase.dialogVisible"
    :title="title"
    width="50%"
    :show-close="false"
    center
    :before-close="close"
  >
    <GreateTokens @parent="getApiKeys" />
  </el-dialog>
</template>
<script setup lang="ts">
import { ref, reactive, onMounted } from "vue";
import { ArrowRight } from "@element-plus/icons-vue";
import AppFooter from "@/components/AppFooter.vue";
import { useBaseStore } from "@/store/base";
import GreateTokens from "./GreateTokens.vue";
import { queryApiKeys, deleteApiKeys } from "@/api/show";
const useBase = useBaseStore();
const centerDialogVisible = ref(false);
const title = ref();
const close = () => {};
const showTokens = () => {
  useBase.dialogVisible = true;
  title.value = "Generate new token";
};
//获取数据
const tableData = ref();
const getApiKeys = () => {
  queryApiKeys().then((res: any) => {
    tableData.value = res;
  });
};
//删除数据
const deletId = ref();
const deletKeys = () => {
  deleteApiKeys(deletId.value).then((res) => {
    centerDialogVisible.value = false;
    getApiKeys();
  });
};
//打开dialog
const openDialog = (val: any) => {
  centerDialogVisible.value = true;
  deletId.value = val;
};
onMounted(() => getApiKeys());
</script>
<style scoped lang="scss">
.main {
  padding: 42px 120px;
  position: relative;
  background: #f5f6f8;
  .table {
    margin-top: 48px;
    background: #ffffff;
    padding: 40px;
    .title {
      display: flex;
      justify-content: center;
      font-size: 24px;
      font-family: FZLTHJW--GB1-0, FZLTHJW--GB1;
      font-weight: normal;
      color: #000000;
      line-height: 32px;
      margin-bottom: 40px;
    }
    .table-th {
      height: 108px;
      padding: 20px;
      background: rgba(0, 47, 167, 0.04);
      position: relative;
      display: flex;
      align-items: center;
      margin-bottom: 16px;
      .th-title {
        font-size: 18px;
        font-family: FZLTHJW--GB1-0, FZLTHJW--GB1;
        font-weight: normal;
        color: #002fa7;
        line-height: 24px;
        margin-bottom: 16px;
        .small {
          margin-top: 16px;
          font-size: 14px;
          font-family: PingFangSC-Regular, PingFang SC;
          font-weight: 400;
          color: #000000;
          line-height: 22px;
        }
      }
      .th {
        display: flex;
        align-items: center;
      }
      .th-btn {
        position: absolute;
        padding-right: 20px;
        right: 0;
        .btn-title {
          margin-right: 16px;
        }
      }
    }
  }
  .btn {
    height: 32px;
    border: 1px solid #00195a;
    color: #00195a;
    font-size: 14px;
    position: absolute;
    right: 120px;
    display: flex;
    align-items: center;
    padding: 5px 15px;
    cursor: pointer;
  }
}
footer {
  position: absolute;
  width: 100%;
  bottom: 0;
}
.textCenter {
  display: flex;
  justify-content: center;
}
</style>
