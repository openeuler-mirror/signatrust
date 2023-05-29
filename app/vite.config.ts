import path from 'path';
import { defineConfig } from 'vite';
import vue from '@vitejs/plugin-vue';
import Icons from 'unplugin-icons/vite';
import { FileSystemIconLoader } from 'unplugin-icons/loaders';
import vueJsx from '@vitejs/plugin-vue-jsx';
export default defineConfig({
  base: '/',
  build: {
    outDir: path.resolve(__dirname, './dist'),
  },
  resolve: {
    alias: {
      '@/': `${path.resolve(__dirname, './src')}/`,
    },
  },
  plugins: [
    vue(),
    vueJsx({}),
    Icons({
      compiler: 'vue3',
      customCollections: {
        app: FileSystemIconLoader(
          path.resolve(__dirname, '../shared/svg-icons')
        ),
      },
    }),
  ],
  server: {
    proxy: {
      '/api': {
        target: 'https://signatrust.test.osinfra.cn/',
        secure: false,
        changeOrigin: true,
      },
      '/oneid': {
        target: 'https://omapi.osinfra.cn/',
        secure: false,
        changeOrigin: true,
      },
    },
  },
});
