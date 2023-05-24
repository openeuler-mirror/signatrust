<template>
  <el-form
    label-position="right"
    label-width="200px"
    :model="formLabelAlign"
    :rules="rules"
    ref="ruleFormRef"
  >
    <div class="table">
      <el-form-item label="Name" prop="name">
        <el-input
          v-model="formLabelAlign.name"
          placeholder="name should be identical , ‘:’ character is not allowed"
        />
      </el-form-item>
      <el-form-item label="Description" prop="description">
        <el-input
          v-model="formLabelAlign.description"
          placeholder="used for openeuler 22:03 release"
        />
      </el-form-item>
      <el-form-item label="Type">
        <el-input placeholder="X509" disabled />
      </el-form-item>
      <el-form-item label="Expire">
        <el-date-picker
          v-model="formLabelAlign.expire_at"
          type="date"
          placeholder="Pick a day"
          :disabled-date="pickerOptions"
        />
      </el-form-item>
      <el-form-item label="Visibility">
        <el-radio-group v-model="formLabelAlign.visibility" class="ml-4"  @change="getChange()">
          <el-radio label="private" title="123">Private</el-radio>
          <el-radio label="public" title="123">Public</el-radio>
        </el-radio-group>
      </el-form-item>
    </div>
    <div class="detail">
      <span class="sp">Details</span>
      <div class="table">
        <div class="sel">
          <el-form-item label="Key Type">
            <el-select v-model="formLabelAlign.key_type" class="m-2" size="small">
              <el-option
                v-for="item in optionsType"
                :key="item.value"
                :label="item.label"
                :value="item.value"
              />
            </el-select>
          </el-form-item>
          <el-form-item label="Key Size">
            <el-select v-model="formLabelAlign.key_length" class="m-2" size="small">
              <el-option
                v-for="item in optionsSize"
                :key="item.value"
                :label="item.label"
                :value="item.value"
              />
            </el-select>
          </el-form-item>
          <el-form-item label="Digest">
            <el-select v-model="formLabelAlign.digest_algorithm" class="m-2" size="small">
              <el-option
                v-for="item in optionsDigest"
                :key="item.value"
                :label="item.label"
                :value="item.value"
              />
            </el-select>
          </el-form-item>
        </div>
        <el-form-item label="Common Name(CN)" prop="common_name">
          <el-input v-model="formLabelAlign.common_name" placeholder="Common Name(CN)" />
        </el-form-item>
        <el-form-item label="Locality(L)" prop="locality">
          <el-input v-model="formLabelAlign.locality" placeholder="Locality(L)" />
        </el-form-item>
        <el-form-item label="Organizational Unit(OU)" prop="organizational_unit">
          <el-input
            v-model="formLabelAlign.organizational_unit"
            placeholder="Organizational Unit(OU)"
          />
        </el-form-item>
        <el-form-item label="State or ProvinceName(ST)" prop="province_name">
          <el-input v-model="formLabelAlign.province_name" placeholder="GuangDong" />
        </el-form-item>
        <el-form-item label="Organization(O)" prop="organization">
          <el-input v-model="formLabelAlign.organization" placeholder="openEuler" />
        </el-form-item>
        <el-form-item label="Country Name(C)" prop="country_name">
          <el-input v-model="formLabelAlign.country_name" placeholder="CN" />
        </el-form-item>
      </div>
    </div>
    <div class="dialog-footer">
      <el-button @click="resetForm(ruleFormRef)">Cancel</el-button>
      <el-button type="primary" @click="submitForm(ruleFormRef)"> Confirm </el-button>
    </div>
  </el-form>
</template>
<script setup lang="ts">
import { reactive, ref, watch, computed } from "vue";
import { useBaseStore } from "@/store/base";
import { queryNewKey, headName  } from "@/api/show";
import type { FormInstance, FormRules } from "element-plus";
import { originalDate } from "@/shared/utils/helper";
import { useDataStore } from "@/store/data";
const useData = useDataStore();
const ruleFormRef = ref<FormInstance>();
const useBase = useBaseStore();
const formLabelAlign = reactive<any>({
  name: "",
  expire_at: "",
  description: "",
  visibility: "private",
  digest_algorithm: "none",
  key_type: "rsa",
  key_length: "2048",
  common_name: "",
  locality: "",
  organizational_unit: "",
  organization: "",
  province_name: "",
  country_name: "",
});
const param = ref({
  name: "test-x509",
  description: "hello world",
  key_type: "x509",
  visibility: "public",
  attributes: {
    digest_algorithm: "sha2_256",
    key_type: "rsa",
    key_length: "2048",
    common_name: "common name",
    organizational_unit: "organizational_unit",
    organization: "organization",
    locality: "locality",
    province_name: "province_name",
    country_name: "country_name",
  },
  create_at: originalDate(new Date()),
  expire_at: "2024-05-12 22:10:57+08:00",
});
const optionsType = [
  {
    value: "rsa",
    label: "RSA",
  },
  {
    value: "dsa",
    label: "DSA",
  },
];
const optionsSize = [
  {
    value: "2048",
    label: "2048",
  },
  {
    value: "3072",
    label: "3072",
  },
  {
    value: "4096",
    label: "4096",
  },
];
const optionsDigest = [
  {
    value: "none",
    label: "none",
  },
  {
    value: "md5",
    label: "md5",
  },
  {
    value: "sha1",
    label: "sha1",
  },
  {
    value: "sha2_224",
    label: "sha2_224",
  },
  {
    value: "sha2_256",
    label: "sha2_256",
  },
  {
    value: "sha2_384",
    label: "sha2_384",
  },
  {
    value: "sha2_512",
    label: "sha2_512",
  }
];

//删除掉
const cleanForm = () => {
  const keys = Object.keys(formLabelAlign);
  keys.forEach((key) => {
    formLabelAlign[key] = "";
  });
  formLabelAlign.digest_algorithm = "none";
  formLabelAlign.key_length = "2048";
  formLabelAlign.key_type = "rsa";
  formLabelAlign.visibility = "private";
};
// 表单校验规则
/* 姓名 */
const isName = (rule: any, value: any, callback: any) => {
  if (!value) {
    callback();
  } else {
    const reg = /^[a-zA-Z]{4,20}$/;
    const name = reg.test(value);
    if (!name) {
      callback(new Error("The value contains 4 to 20 English characters"));
    } else {
      const param = ref({
        name: value,
        visibility: computed(() => formLabelAlign.visibility),
      });
      headName(param.value)
        .then(() => callback())
        .catch(() => callback(new Error("Duplicate name")));
    }
  }
};
/* 描述 */
const isDesc = (rule: any, value: any, callback: any) => {
  if (!value) {
    callback(console.log("avc"));
  } else {
    const reg = /^[a-zA-Z]{1,100}$/;
    const desc = reg.test(value);
    if (!desc) {
      callback(new Error("The value contains a maximum of 100 English characters"));
    } else {
      callback();
    }
  }
};
/* 公共校验 */
const isCommon = (rule: any, value: any, callback: any) => {
  if (!value) {
    callback(console.log("avc"));
  } else {
    const reg = /^[a-zA-Z]{1,30}$/;
    const desc = reg.test(value);
    if (!desc) {
      callback(new Error("The value contains 1 to 30 English characters"));
    } else {
      callback();
    }
  }
};
const isCountry = (rule: any, value: any, callback: any) => {
  if (!value) {
    callback(console.log("avc"));
  } else {
    const reg = /^[a-zA-Z]{2,2}$/;
    const desc = reg.test(value);
    if (!desc) {
      callback(new Error("The value contains 2 English characters only"));
    } else {
      callback();
    }
  }
};

const rules = reactive<FormRules>({
  name: [
    { required: true, message: "please enter", trigger: "blur" },
    { validator: isName, trigger: ["blur","change"] },
  ],
  description: [
    { required: true, message: "please enter", trigger: "blur" },
    { validator: isDesc, trigger: ["blur","change"]  },
  ],
  common_name: [
    { required: true, message: "please enter", trigger: "blur" },
    { validator: isCommon, trigger: "blur" },
  ],
  country_name: [
    { required: true, message: "please enter", trigger: "blur" },
    { validator: isCountry, trigger: ["blur", "change"], },
  ],
  locality:[
    { required: true, message: "please enter", trigger: "blur" },
    { validator: isCommon, trigger: "blur" },
  ],
  organizational_unit:[
    { required: true, message: "please enter", trigger: "blur" },
    { validator: isCommon, trigger: "blur" },
  ],
  organization:[
    { required: true, message: "please enter", trigger: "blur" },
    { validator: isCommon, trigger: "blur" },
  ],
  province_name:[
    { required: true, message: "please enter", trigger: "blur" },
    { validator: isCommon, trigger: "blur" },
  ],
});
//表单请求
const newKey = () => {
  queryNewKey(param.value).then((res) => {
    useBase.dialogVisible = false;
    useData.getTableData();
    useData.getPriTableData();
  });
};
//获取表单值
const getData = () => {
  param.value.name = formLabelAlign.name;
  param.value.description = formLabelAlign.description;
  param.value.visibility = formLabelAlign.visibility;
  param.value.expire_at = originalDate(formLabelAlign.expire_at);
  param.value.attributes.digest_algorithm = formLabelAlign.digest_algorithm;
  param.value.attributes.key_length = formLabelAlign.key_length;
  param.value.attributes.key_type = formLabelAlign.key_type;
  param.value.attributes.common_name = formLabelAlign.common_name;
  param.value.attributes.organizational_unit = formLabelAlign.organizational_unit;
  param.value.attributes.organization = formLabelAlign.organization;
  param.value.attributes.locality = formLabelAlign.locality;
  param.value.attributes.province_name = formLabelAlign.province_name;
  param.value.attributes.country_name = formLabelAlign.country_name;
};
//提交表单
const submitForm = async (formEl: FormInstance | undefined) => {
  if (!formEl) return;
  await formEl.validate((valid, fields) => {
    if (valid) {
      getData();
      newKey(); 
    } else {
      return false;
    }
  });
  cleanForm()
  formEl.resetFields();
};
//关闭表单
const resetForm = (formEl: FormInstance | undefined) => {
  if (!formEl) return;
  useBase.dialogVisible = false;
  cleanForm()
  formEl.resetFields();
};
const pickerOptions = (time: any) => {
  return time?.getTime() <= new Date().getTime();
};

//改变radio
const getChange = () => {
  formLabelAlign.name = "";
};
</script>
<style scoped lang="scss">
.detail {
  background: #f5f6f8;
  padding: 24px;

  .sp {
    font-size: 18px;
    font-family: PingFangSC-Regular, PingFang SC;
    font-weight: 400;
    color: #000000;
    line-height: 26px;
    margin: 24px 0px 31px 150px;
  }
}
.table {
  padding: 24px;
  .sel {
    display: flex;
    .m-2 {
      padding-right: 24px;
    }
  }
}
.dialog-footer button:first-child {
  margin-right: 10px;
}
.dialog-footer {
  margin-top: 30px;
  display: flex;
  justify-content: center;
  align-items: center;
}
</style>
<style lang="scss">
.sel {
  .el-select .el-input__inner {
    width: 80px;
    height: 24px;
    margin-right: 2px;
    margin-left: 2px;
  }
}
</style>
