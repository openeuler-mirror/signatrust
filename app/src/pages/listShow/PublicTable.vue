<template>
  <div class="title">Public Keys</div>
  <div class="smalltitle">
    ({{ useData.pgpData }} openPGP keys,{{ useData.x509Data }} X509 keys)
  </div>
  <div class="search">
    <el-input
      v-model="searchInput"
      placeholder="Search by Name"
      :prefix-icon="Search"
      @change="querySearch"
      @clear="clearSearchInput"
      :clearable="true"
    />
  </div>
  <el-table ref="multipleTableRef" :data="useData.tableData">
    <el-table-column label="Name" show-overflow-tooltip prop="name" width="150">
    </el-table-column>
    <el-table-column prop="key_state" label="State" align="left" width="80" />
    <el-table-column label="Fingerprint" align="left" show-overflow-tooltip>
      <template #default="scope">
        <img
          src="@/assets/copy.png"
          alt=""
          style="margin-left: 5px"
          :data-clipboard-text="scope.row.fingerprint"
          @click="copy"
          class="tag"
        />
        {{ scope.row.fingerprint }}
      </template>
    </el-table-column>
    <el-table-column
      prop="description"
      label="Descirption"
      align="left"
      width="200"
      show-overflow-tooltip
    />
    <el-table-column
      prop="key_type"
      label="Key Type"
      align="left"
      show-overflow-tooltip
      width="90"
    />
    <el-table-column
      prop="create_at"
      label="Create Time"
      align="left"
      show-overflow-tooltip
      width="200"
    />
    <el-table-column
      prop="expire_at"
      label="Expire Time"
      align="left"
      show-overflow-tooltip
      width="200"
    >
    </el-table-column>
    <el-table-column
      prop="attributes.key_type"
      label="Key Algorithm"
      align="left"
      width="120"
      show-overflow-tooltip
    />
    <el-table-column
      prop="attributes.digest_algorithm"
      label="Digest Algorithm"
      align="left"
      width="140"
      show-overflow-tooltip
    />
    <el-table-column
      prop="attributes.key_length"
      label="Key Size"
      align="left"
      show-overflow-tooltip
      width="90"
    />
    <el-table-column
      prop="user"
      label="Author"
      align="left"
      show-overflow-tooltip
      width="80"
    />
    <el-table-column fixed="right" label="Operations" width="400">
      <template #default="scope">
        <el-button
          link
          type="primary"
          size="small"
          @click="exportData(scope.row.id, scope.row.name)"
          >Export</el-button
        >|
        <el-button
          link
          type="primary"
          size="small"
          @click="deleteData(scope.row.id, 'delete')"
          >Delete</el-button
        ><span v-if="scope.row.key_state === 'disabled'"
          >|
          <el-button
            link
            type="primary"
            size="small"
            @click="enableData(scope.row.id, 'enable')"
            >Enable</el-button
          ></span
        >
        <span v-if="scope.row.key_state === 'enabled'"
          >|
          <el-button
            link
            type="primary"
            size="small"
            @click="disableData(scope.row.id, 'disable')"
            >Disable</el-button
          ></span
        ><span v-if="scope.row.key_state === 'disabled'"
          >|
          <el-button
            link
            type="primary"
            size="small"
            @click="requestData(scope.row.id, 'request')"
            >Request Delete</el-button
          ></span
        ><span v-else
          >|
          <el-button link type="" size="small" disabled>Request Delete</el-button></span
        >
      </template>
    </el-table-column>
  </el-table>
  <div class="demo-pagination-block">
    <el-pagination
      class="o-pagination"
      :currentPage="useData.pagination.currentPage"
      v-model:page-size="useData.pagination.pageSize"
      :page-sizes="[10, 20, 50]"
      background
      layout="sizes,prev, pager, next,slot, jumper"
      :total="useData.pagination.totalCount"
      @current-change="handleCurrentChange"
      @size-change="sizeChange"
      ><span
        >{{ useData.pagination.currentPage }}/{{
          Math.ceil(useData.pagination.totalCount / useData.pagination.pageSize)
        }}</span
      ></el-pagination
    >
  </div>
  <el-dialog v-model="dialogVisible" title="Prompt Message" width="30%" center>
    <span class="textCenter"> Please confirm again </span>

    <div class="dialog-footer">
      <el-button @click="dialogVisible = false">Cancel</el-button>
      <el-button type="primary" @click="confirm()"> Confirm </el-button>
    </div>
  </el-dialog>
</template>
<script setup lang="ts">
import { ref, onMounted } from "vue";
import { Search } from "@element-plus/icons-vue";
import { ElMessage } from "element-plus";
import Clipboard from "clipboard";
import { useDataStore } from "@/store/data";
import {
  queryDeleteKey,
  queryDisableKey,
  queryEnableKey,
  queryExportKey,
  queryRequestKey,
} from "@/api/show";
const dialogVisible = ref(false);
const useData = useDataStore();
const searchInput = ref();
// 显示第几页
const handleCurrentChange = (val: any) => {
  // 改变默认的页数
  if (val?.isTrusted) {
  } else {
    useData.pagination.currentPage = val;
    useData.getTableData();
  }
};
// 改变每页显示条数
const sizeChange = (val: any) => {
  useData.pagination.pageSize = val;
  useData.pagination.currentPage = 1;
  useData.getTableData();
};
const getAllData = () => {
  useData.getTableData();
};
const copy = () => {
  let clipboard = new Clipboard(".tag");
  clipboard.on("success", (e) => {
    ElMessage({
      message: "复制成功",
      type: "success",
    });
    clipboard.destroy();
  });
  clipboard.on("error", (e) => {
    ElMessage.error("复制失败");
    clipboard.destroy();
  });
};

//导出txt
const exportText = (dataStr: any) => {
  const name = exportName.value;
  const element = document.createElement("a");
  element.setAttribute(
    "href",
    "data:pgp/plain;charset=utf-8," + encodeURIComponent(dataStr)
  );
  element.setAttribute("download", name);
  element.style.display = "none";
  element.click();
};

const deleteData = (val: any, value: any) => {
  dialogVisible.value = true;
  witchChange.value = value;
  witchOne.value = val;
};
const enableData = (val: any, value: any) => {
  dialogVisible.value = true;
  witchChange.value = value;
  witchOne.value = val;
};
const disableData = (val: any, value: any) => {
  dialogVisible.value = true;
  witchChange.value = value;
  witchOne.value = val;
};
const exportName = ref();
const exportData = (val: any, value: any) => {
  queryExportKey(val).then(
    (res: any) => exportText(res.public_key),
    (exportName.value = value)
  );
};
const requestData = (val: any, value: any) => {
  dialogVisible.value = true;
  witchChange.value = value;
  witchOne.value = val;
};
onMounted(() => getAllData());

//搜索
const querySearch = () => {
  useData.pagination.searchInput = searchInput.value;
  getAllData();
};
//清空搜索
const clearSearchInput = () => {
  getAllData();
};
//再次确认
const witchChange = ref();
const witchOne = ref();
const confirm = () => {
  if (witchChange.value === "delete") {
    queryDeleteKey(witchOne.value).then((res) => getAllData());
    dialogVisible.value = false;
  } else if (witchChange.value === "enable") {
    queryEnableKey(witchOne.value).then((res) => getAllData());
    dialogVisible.value = false;
  } else if (witchChange.value === "disable") {
    queryDisableKey(witchOne.value).then((res) => getAllData());
    dialogVisible.value = false;
  } else if (witchChange.value === "request") {
    queryRequestKey(witchOne.value).then((res) => getAllData());
    dialogVisible.value = false;
  }
};
</script>
<style scoped lang="scss">
.search {
  margin-bottom: 24px;
  display: flex;
}
.title {
  margin-bottom: 14px;
  font-size: 24px;
  font-family: FZLTHJW--GB1-0, FZLTHJW--GB1;
  color: #000000;
  line-height: 32px;
}
.smalltitle {
  margin-bottom: 10px;
  font-size: 14px;
  color: #999999;
}
.el-button + .el-button {
  margin: 0px 2px;
}
.el-button {
  padding-right: 4px;
  --el-color-primary: #000;
  --el-color-primary-light-5: #002fa7;
}
.demo-pagination-block {
  margin-top: 60px;
  display: flex;
  justify-content: center;
  align-items: center;
}
.tag {
  color: #002fa7;
  font-size: 14px;
  font-family: FZLTHJW--GB1-0, FZLTHJW--GB1;
  width: 18px;
  height: 18px;
  cursor: pointer;
}

.dialog-footer button:first-child {
  margin-right: 10px;
}
.dialog-footer {
  margin-top: 30px;
  display: flex;
  justify-content: center;
  align-items: center;
  .el-button + .el-button {
    margin: 0px 0px !important;
  }
  .el-button {
    padding-right: 8px !important;
    padding-left: 8px !important;
    --el-color-primary: #002fa7 !important;
    --el-color-primary-light-5: #002fa7;
  }
}
</style>
