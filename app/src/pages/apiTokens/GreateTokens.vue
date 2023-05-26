<template>
  <el-form label-position="top" label-width="200px" :model="formLabelAlign">
    <div class="table">
      <el-form-item label="Expiration">
        <div class="test">
          <el-input placeholder="180 days" disabled />
        </div>
      </el-form-item>
      <el-form-item label="Description">
        <el-input
          v-model="formLabelAlign.description"
          placeholder="used for openeuler 22:03 release"
        />
      </el-form-item>
    </div>

    <div class="dialog-footer">
      <el-button @click="cancle">Cancel</el-button>
      <el-button type="primary" @click="getKeys()"> Confirm </el-button>
    </div>
  </el-form>
</template>

<script setup lang="ts">
import { reactive, ref, watch } from "vue";
import { useBaseStore } from "@/store/base";
import { getApiKeys } from "@/api/show";
const useBase = useBaseStore();
const formLabelAlign = reactive<any>({
  description: "",
});
const cleanForm = () => {
  const keys = Object.keys(formLabelAlign);
  keys.forEach((key) => {
    formLabelAlign[key] = "";
  });
};
const cancle = () => {
  useBase.dialogVisible = false;
  cleanForm();
  emit("parent");
};
//接收父组件的parent方法
const emit = defineEmits(["parent"]);
const getKeys = () => {
  const param = {
    description: formLabelAlign.description,
  };
  getApiKeys(param).then(() => {
    cancle();  
  });
};
</script>
<style scoped lang="scss">
.dialog-footer button:first-child {
  margin-right: 10px;
}
.dialog-footer {
  margin-top: 30px;
  display: flex;
  justify-content: center;
  align-items: center;
}
.test {
  width: auto;
}
</style>
