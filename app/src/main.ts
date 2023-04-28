import { createApp } from 'vue'
import App from './App.vue'
import './shared/styles/index.scss';
import './shared/ele-reset.ts'
import OpenDesign from 'opendesign';
import { router } from './router';
import ElementPlus from 'element-plus'
const app = createApp(App)
app.use(router)
app.use(OpenDesign);
app.use(ElementPlus)
app.mount('#app')
