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
      @input="querySearch"
      @clear="clearSearchInput"
      :clearable="true"
    />
  </div>
  <el-table ref="multipleTableRef" :data="useData.tableData">
    <el-table-column label="Name" show-overflow-tooltip prop="name" width="150">
    </el-table-column>
    <el-table-column prop="key_state" label="State" align="left" width="150">
      <template #default="scope">
        <span
          :title="
            scope.row.request_delete_users || scope.row.request_revoke_users
          "
          >{{ scope.row.key_state }}</span
        >
      </template>
    </el-table-column>
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
      prop="user_email"
      label="Author"
      align="left"
      width="120"
      show-overflow-tooltip
    />
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
      width="180"
    >
      <template #default="scope">
        {{ getKeyType(scope.row.key_type) }}
      </template>
    </el-table-column>
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
    >
      <template #default="scope">
        {{ scope.row.attributes.key_type.toUpperCase() }}
      </template>
    </el-table-column>
    <el-table-column
      prop="attributes.digest_algorithm"
      label="Digest Algorithm"
      align="left"
      width="150"
      show-overflow-tooltip
    >
      <template #default="scope">
        {{ scope.row.attributes.digest_algorithm.toUpperCase() }}
      </template>
    </el-table-column>
    <el-table-column
      prop="attributes.key_length"
      label="Key Size"
      align="left"
      show-overflow-tooltip
      width="90"
    />
    <el-table-column fixed="right" label="Operations" width="200">
      <template #default="scope">
        <el-dropdown trigger="click">
          <span
            class="el-dropdown-link"
            style="margin-right: 30px; cursor: pointer; color: #002fa7"
          >
            View<el-icon class="el-icon--right"><arrow-down /></el-icon>
          </span>
          <template #dropdown>
            <el-dropdown-menu>
              <el-dropdown-item
                @click="exportData(scope.row.id, scope.row.name, 'certificate')"
                :disabled="
                  scope.row.key_type === 'x509ca' ||
                  scope.row.key_type === 'x509ica' ||
                  scope.row.key_type === 'x509ee'
                    ? false
                    : true
                "
                >Certificate</el-dropdown-item
              >
              <el-dropdown-item
                @click="exportData(scope.row.id, scope.row.name, 'publicKey')"
                :disabled="scope.row.key_type === 'pgp' ? false : true"
                >Pubilc Key</el-dropdown-item
              >
              <el-dropdown-item
                @click="exportData(scope.row.id, scope.row.name, 'crl')"
                :disabled="
                  scope.row.key_type === 'x509ca' ||
                  scope.row.key_type === 'x509ica'
                    ? false
                    : true
                "
                >CRL</el-dropdown-item
              >
            </el-dropdown-menu>
          </template>
        </el-dropdown>
        <el-dropdown trigger="click">
          <span
            class="el-dropdown-link"
            style="cursor: pointer; color: #002fa7"
          >
            Actions<el-icon class="el-icon--right"><arrow-down /></el-icon>
          </span>
          <template #dropdown>
            <el-dropdown-menu>
              <el-dropdown-item
                :disabled="
                  scope.row.key_state === 'pending_delete' ? false : true
                "
                @click="getData(scope.row.id, 'cancel delete')"
                >Cancel Delete</el-dropdown-item
              >
              <el-dropdown-item
                :disabled="scope.row.key_state === 'disabled' ? false : true"
                @click="getData(scope.row.id, 'enable')"
                >Enable</el-dropdown-item
              >
              <el-dropdown-item
                :disabled="scope.row.key_state === 'enabled' ? false : true"
                @click="getData(scope.row.id, 'disable')"
                >Disable</el-dropdown-item
              >
              <el-dropdown-item
                :disabled="scope.row.key_state !== 'enabled' ? false : true"
                @click="getData(scope.row.id, 'delete')"
                >Delete</el-dropdown-item
              >
              <el-dropdown-item
                :disabled="
                  scope.row.key_type === 'x509ica' ||
                  scope.row.key_type === 'x509ee'
                    ? false
                    : true
                "
                @click="getData(scope.row.id, 'revoke')"
                >Revoke</el-dropdown-item
              >
              <el-dropdown-item
                :disabled="
                  scope.row.key_state === 'pending_revoke' ? false : true
                "
                @click="getData(scope.row.id, 'pending_revoke')"
                >Cancel Revoke</el-dropdown-item
              >
            </el-dropdown-menu>
          </template>
        </el-dropdown>
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
  <el-dialog
    v-model="dialogVisible"
    title="Confirmation"
    width="30%"
    center
    :show-close="false"
    :before-close="close"
  >
    <span class="textCenter">
      Enter
      <span style="color: red">{{
        witchChange !== 'pending_revoke'
          ? witchChange.toUpperCase()
          : 'Cancel Revoke'
      }}</span>
      in the text box below to confirm the revoction</span
    >
    <div style="margin-top: 20px">
      <el-input
        v-model="textValue"
        :placeholder="`Enter ${
          witchChange !== 'pending_revoke'
            ? witchChange.toUpperCase()
            : 'Cancel Revoke'
        } to confirm the revocation`"
        @input="getText()"
        onpaste="return false;"
      />
    </div>
    <div style="margin-top: 20px" v-if="witchChange === 'revoke'">
      <span style="margin-right: 20px; color: red">Reason</span>
      <el-select
        v-model="selectValue"
        class="m-2"
        :placeholder="selectValue.toUpperCase()"
      >
        <el-option
          v-for="item in selectOptions"
          :key="item.value"
          :label="item.value.toUpperCase()"
          :value="item.value"
        />
      </el-select>
    </div>

    <div class="dialog-footer">
      <el-button @click="cleanText()">Cancel</el-button>
      <el-button type="primary" @click="confirm()" :disabled="trueText">
        Confirm
      </el-button>
    </div>
  </el-dialog>
  <el-dialog
    v-model="dialogTwoVisible"
    :title="exportName?.toUpperCase()"
    width="30%"
    center
    show-close
  >
    <el-input v-model="copyValue"  type="textarea" :disabled="false" autosize/>
    <div
      :data-clipboard-text="copyValue"
      class="tag"
      @click="copy()"
      style="margin: 30px auto"
    >
      <button
        style="
          padding: 10px 25px;
          background-color: #002fa7;
          color: #fff;
          cursor: pointer;
        "
      >
        Copy
      </button>
    </div>
  </el-dialog>
</template>
<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { Search } from '@element-plus/icons-vue';
import { ElMessage } from 'element-plus';
import Clipboard from 'clipboard';
import { useDataStore } from '@/store/data';
import {
  queryDeleteKey,
  queryDisableKey,
  queryEnableKey,
  queryRevokeKey,
  queryRequestKey,
  queryCertificate,
  queryCancelRevoke,
  queryCrl,
  queryPublicKey,
} from '@/api/show';
import { ArrowDown } from '@element-plus/icons-vue';
const dialogVisible = ref(false);
const dialogTwoVisible = ref(false);
const useData = useDataStore();
const searchInput = ref();
const textValue = ref();
const trueText = ref(true);
const copyValue = ref();
//验证输入
const close = () => {};
const getText = () => {
  if (textValue.value === witchChange.value.toUpperCase()) {
    trueText.value = false;
  } else {
    trueText.value = true;
  }
};
const cleanText = () => {
  dialogVisible.value = false;
  dialogTwoVisible.value = false;
  textValue.value = '';
  trueText.value = true;
  selectValue.value = 'unspecified';
};
//选择框
const selectValue = ref('unspecified');

const selectOptions = [
  {
    value: 'unspecified',
  },
  {
    value: 'key_compromise',
  },
  {
    value: 'ca_compromise',
  },
  {
    value: 'affiliation_changed',
  },
  {
    value: 'superseded',
  },
  {
    value: 'cessation_of_operation',
  },
  {
    value: 'certificate_hold',
  },
  {
    value: 'privilege_withdrawn',
  },
  {
    value: 'aa_compromise',
  },
];
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
  let clipboard = new Clipboard('.tag');
  clipboard.on('success', e => {
    ElMessage({
      message: 'Successfully copied',
      type: 'success',
    });
    clipboard.destroy();
  });
  clipboard.on('error', e => {
    ElMessage.error('Failed to copy');
    clipboard.destroy();
  });
};

//导出txt
const exportText = (dataStr: any) => {
  const name = exportName.value;
  const element = document.createElement('a');
  element.setAttribute(
    'href',
    'data:pgp/plain;charset=utf-8,' + encodeURIComponent(dataStr)
  );
  element.setAttribute('download', name);
  element.style.display = 'none';
  element.click();
};

const getData = (val: any, value: any) => {
  dialogVisible.value = true;
  witchChange.value = value;
  witchOne.value = val;
};
const exportName = ref();
const exportData = (val: any, value: any, name: any) => {
  if (name === 'certificate') {
    queryCertificate(val)
      .then(
        (res: any) => {
          (dialogTwoVisible.value = true), (copyValue.value = res);
        }
        // exportText(res.public_key),
        //   (exportName.value = value),
      )
      .catch((res: any) => {
        ElMessage.error(res.response.data.detail);
      });
  } else if (name === 'crl') {
    queryCrl(val)
      .then((res: any) => {
        (dialogTwoVisible.value = true), (copyValue.value = res);
      })
      .catch((res: any) => {
        ElMessage.error(res.response.data.detail);
      });
  } else if (name === 'publicKey') {
    queryPublicKey(val)
      .then((res: any) => {
        (dialogTwoVisible.value = true), (copyValue.value = res);
      })
      .catch((res: any) => {
        ElMessage.error(res.response.data.detail);
      });
  }
  exportName.value = name;
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
  if (witchChange.value === 'cancel delete') {
    queryDeleteKey(witchOne.value)
      .then(res => getAllData())
      .catch((res: any) => {
        ElMessage.error(res.response.data.detail);
      });
  } else if (witchChange.value === 'enable') {
    queryEnableKey(witchOne.value)
      .then(res => getAllData())
      .catch((res: any) => {
        ElMessage.error(res.response.data.detail);
      });
  } else if (witchChange.value === 'disable') {
    queryDisableKey(witchOne.value)
      .then(res => getAllData())
      .catch((res: any) => {
        ElMessage.error(res.response.data.detail);
      });
  } else if (witchChange.value === 'delete') {
    queryRequestKey(witchOne.value)
      .then(res => getAllData())
      .catch((res: any) => {
        ElMessage.error(res.response.data.detail);
      });
  } else if (witchChange.value === 'revoke') {
    const val = {
      reason: selectValue.value,
    };
    queryRevokeKey(witchOne.value, val)
      .then(res => getAllData())
      .catch((res: any) => {
        ElMessage.error(res.response.data.detail);
      });
  } else if (witchChange.value === 'pending_revoke') {
    queryCancelRevoke(witchOne.value)
      .then((res: any) => getAllData())
      .catch((res: any) => {
        ElMessage.error(res.response.data.detail);
      });
  }
  cleanText();
};

//key type映射
const getKeyType = (val: any) => {
  switch (val) {
    case 'pgp':
      return 'OpenPGP';
    case 'x509ca':
      return 'X509 CA';
    case 'x509ica':
      return 'X509 Intermediate CA';
    case 'x509ee':
      return 'X509 End Entity';
  }
};
</script>
<style scoped lang="scss">
.comment {
  white-space: pre-wrap;
}

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
  // --el-color-primary: #000;
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
