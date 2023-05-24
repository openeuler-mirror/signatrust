import { createApp } from 'vue'
import App from './App.vue'
import './shared/styles/index.scss';
import './shared/ele-reset.ts'
import OpenDesign from 'opendesign';
import { router } from './router';
import ElementPlus from 'element-plus'
import 'element-plus/theme-chalk/index.css'
import './before.ts';
import { createPinia } from 'pinia';
const app = createApp(App)
app.use(router)
app.use(ElementPlus)
app.use(createPinia());
app.use(OpenDesign);
app.mount('#app')
