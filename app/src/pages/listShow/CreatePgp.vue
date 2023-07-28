<template>
  <el-form
    label-position="right"
    label-width="auto"
    :model="formLabelAlign"
    :rules="rules"
    ref="ruleFormRef"
  >
    <div class="table">
      <el-form-item label="Name" prop="name">
        <el-input
          v-model="formLabelAlign.name"
          placeholder="Name is identical, ‘:’ character is not allowed"
        />
      </el-form-item>
      <el-form-item label="Description" prop="description">
        <el-input
          v-model="formLabelAlign.description"
          placeholder="Description of this key"
        />
      </el-form-item>
      <el-form-item label="Type">
        <el-input placeholder="openPGP" disabled />
      </el-form-item>
      <el-form-item label="Expire"  prop="expire_at">
        <el-date-picker
          v-model="formLabelAlign.expire_at"
          type="month"
          placeholder="Choose expire date time"
          :disabled-date="pickerOptions"
        />
      </el-form-item>
      <el-form-item label="Visibility">
        <el-radio-group
          v-model="formLabelAlign.visibility"
          class="ml-4"
          @change="getChange()"
        >
          <!-- <el-radio label="private" title="The private key pairs are managed by yourself, no one else can seen/use your private key pairs.">Private</el-radio> -->
          <el-radio label="public" title="The public key pairs can be created/used by any administrator, but in order to delete it, it require triple confirms from different administrators.">Public</el-radio>
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
          <el-form-item label="Key Size" >
            <el-select v-model="formLabelAlign.key_length" class="m-2" size="small">
              <el-option
                v-for="item in optionsSize"
                :key="item.value"
                :label="item.label"
                :value="item.value"
              />
            </el-select>
          </el-form-item>
          <el-form-item label="Digest Algorithm">
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
        <el-form-item label="Key Email" prop="email">
          <el-input v-model="formLabelAlign.email" placeholder="Email used to identify your key" />
        </el-form-item>
        <el-form-item label="Passphrase (optional)" prop="pass">
          <el-input
            v-model="formLabelAlign.pass"
            placeholder="Passphrase of this key"
            show-password
          />
        </el-form-item>
        <el-form-item label="Passphrase (optional)" prop="paw2">
          <el-input
            placeholder="Input passphrase again"
            v-model="formLabelAlign.paw2"
            show-password
          />
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
import { queryNewKey, headName } from "@/api/show";
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
  visibility: "public",
  paw2: "",
  digest_algorithm: "none",
  key_type: "rsa",
  key_length: "2048",
  email: "",
  pass: "",
});
const param = ref({
  name: "test-pgpd",
  description: "hello world",
  key_type: "pgp",
  visibility: "public",
  attributes: {
    digest_algorithm: "sha2_256",
    key_type: "rsa",
    key_length: "2048",
    email: "test@openeuler.org",
    passphrase: "password",
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
    value: "eddsa",
    label: "EDDSA",
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
  },
  {
    value: "sha3_512",
    label: "sha3_512",
  },
  {
    value: "sha3_256",
    label: "sha3_256",
  },
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
  formLabelAlign.visibility = "public";
};
// 表单校验规则
/* 姓名 */
const isName = (rule: any, value: any, callback: any) => {
  if (!value) {
    callback();
  } else {
    const reg = /^[a-zA-Z0-9-]{4,256}$/;
    const name = reg.test(value);
    if (!name) {
      callback(new Error("The value contains 4 to 256 English characters"));
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
    callback();
  } else {
    const reg = /^[a-zA-Z0-9-\s]{1,200}$/;
    const desc = reg.test(value);
    if (!desc) {
      callback(new Error("The value contains a maximum of 100 English characters"));
    } else {
      callback();
    }
  }
};
/* 密码 */
const isPass = (rule: any, value: any, callback: any) => {
  if (!value) {
    callback();
  } else {
    const reg = /^[a-zA-Z0-9]{4,20}$/;
    const pass = reg.test(value);
    if (!pass) {
      callback(new Error("The value contains 4 to 20 English characters"));
    } else {
      callback();
    }
  }
};
const againPass = (rule: any, value: any, callback: any) => {
  if (value === "" && formLabelAlign.pass === "") {
    callback();
  } else if (value !== formLabelAlign.pass) {
    callback(new Error("Two password mismatches"));
  } else {
    callback();
  }
};
const rules = reactive<FormRules>({
  email: [
    { required: true, message: "Please enter email", trigger: "blur" },
    {
      type: "email",
      message: "Please enter the correct email address",
      trigger: ["blur", "change"],
    },
  ],
  name: [
    { required: true, message: "Please enter"},
    { validator: isName, trigger: ["change"] },
  ],
  description: [
    { required: true, message: "Please enter a description", trigger: "blur" },
    { validator: isDesc, trigger: ["blur", "change"] },
  ],
  pass: [
    { required: false, message: "enter your pass", trigger: "blur" },
    { validator: isPass },
  ],
  paw2: [
    { required: false, message: "enter your pass again", trigger: "blur" },
    { validator: againPass },
  ],
  expire_at: [
    { required: true, message: "Please enter expire", trigger: ["blur", "change"] },
  ],
});
//表单请求
const newKey = () => {
  queryNewKey(param.value).then((res) => {
    useBase.dialogVisible = false;
    useData.getTableData();
    useData.getPriTableData();
    cleanForm();
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
  param.value.attributes.email = formLabelAlign.email;
  param.value.attributes.passphrase = formLabelAlign.pass;
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
};
//关闭表单
const resetForm = (formEl: FormInstance | undefined) => {
  if (!formEl) return;
  useBase.dialogVisible = false;
  cleanForm();
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
      // padding-right: 24px;
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
// .sel {
//   .el-select .el-input__inner {
//     width: 80px;
//     height: 24px;
//     margin-right: 2px;
//     margin-left: 2px;
//   }
// }
</style>
