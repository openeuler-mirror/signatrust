<script setup lang="ts">
import { computed } from 'vue';

import AppContent from './AppContent.vue';

import LogoFooter from '@/assets/footer/footer-logo2.png';
import LogoFooter1 from '@/assets/footer/footer-logo1.png';
import LogoAtom from '@/assets/footer/atom-logo.png';

// 中文友情链接
import LogoBilibili from '@/assets/footer/bilibili.png';
import LogoInfoq from '@/assets/footer/infoq.png';
import LogoJuejin from '@/assets/footer/juejin.png';
import LogoOschina from '@/assets/footer/oschina.png';
import LogoCsdn from '@/assets/footer/csdn.png';
import Logo51cto from '@/assets/footer/51cto.png';

// 公众号、小助手
import CodeTitleXzs from '@/assets/footer/img-xzs.png';
import CodeTitleGzh from '@/assets/footer/img-gzh.png';
import CodeImgXzs from '@/assets/footer/code-xzs.png';
import CodeImgZgz from '@/assets/footer/code-zgz.png';


// 友情链接
const linksData = {
  zh: [
    {
      path: 'https://my.oschina.net/openeuler',
      logo: LogoOschina,
      id: 'oschina',
    },
    {
      path: 'https://blog.csdn.net/openEuler_?spm=1000.2115.3001.5343',
      logo: LogoCsdn,
      id: 'csdn',
    },
    {
      path: 'https://juejin.cn/user/3183782863845454',
      logo: LogoJuejin,
      id: 'juejin',
    },
    {
      path: 'https://space.bilibili.com/527064077/channel/series',
      logo: LogoBilibili,
      id: 'bilibili',
    },
    {
      path: 'https://www.infoq.cn/profile/6E6CE3E2316F28/publish',
      logo: LogoInfoq,
      id: 'infoq',
    },
    {
      path: 'https://blog.51cto.com/u_14948868',
      logo: Logo51cto,
      id: '51cto',
    },
  ],
};

const RIGHT_LIST=[
      {
        NAME: '品牌',
        URL: '/other/brand/',
      },
      {
        NAME: '隐私政策',
        URL: '/other/privacy/',
      },
      {
        NAME: '法律声明',
        URL: '/other/legal/',
      },
      {
        NAME: '服务状态',
        URL: 'https://status.openeuler.org/',
      },
    ];
// 公众号、小助手
const footerCodeList = [
  {
    img: CodeTitleXzs,
    code: CodeImgXzs,
    label: 'openEuler公众号',
  },
  {
    img: CodeTitleGzh,
    code: CodeImgZgz,
    label: 'openEuler小助手',
  },
];

const handleNavClick = (path: string) => {
  if (path.startsWith('https:')) {
    window.open(path, '_blank');
    return;
  }
  const origin = import.meta.env.VITE_OPENEULER_WEBSITE;
  const url = `${origin}/zh${path}`;
  window.open(url, '_blank');
};
</script>

<template>
  <div class="footer">
    <AppContent :pc-top="0" :mobile-top="0">
      <div class="atom">
        <p class="atom-text">openEuler 是由开放原子开源基金会（OpenAtom Foundation）孵化及运营的开源项目</p>
        <a href="https://openatom.cn/home" target="_blank">
          <img :src="LogoAtom" class="atom-logo" alt="" />
        </a>
      </div>
    </AppContent>
    <div class="footer-content">
      <AppContent :pc-top="0" :mobile-top="0">
        <div class="inner">
          <div class="footer-logo">
            <img class="show-pc" :src="LogoFooter" alt="" />
            <img class="show-mo" :src="LogoFooter1" alt="" />
            <p>
              <a
                class="email"
                :href="'mailto:' + 'contact@openeuler.io'"
                target="_blank"
              >
              contact@openeuler.io
              </a>
            </p>
          </div>
          <div class="footer-option">
            <div class="footer-option-item">
              <a
                v-for="link in RIGHT_LIST"
                :key="link.URL"
                href="javascript:;"
                class="link"
                @click="handleNavClick(link.URL)"
                >{{ link.NAME }}</a
              >
            </div>
            <p class="copyright">版权所有 © 2022 openEuler 保留一切权利</p>
          </div>
          <div class="footer-right">
            <div  class="code-box">
              <a
                v-for="(item, index) in footerCodeList"
                :key="index"
                class="code-pop"
                href="javascript:;"
              >
                <img :src="item.img" class="code-img" alt="" />
                <div class="code-layer">
                  <img :src="item.code" alt="" />
                  <p class="txt">{{ item.label }}</p>
                </div>
              </a>
            </div>
            <!-- <div class="footer-links" class="iszh"> -->
              <div class="footer-links" >
              <a
                v-for="item in linksData.zh"
                :key="item.id"
                :href="item.path"
                class="links-logo"
                target="_blank"
              >
                <img :src="item.logo" alt="" />
              </a>
            </div>
          </div>
        </div>
      </AppContent>
    </div>
  </div>
</template>

<style lang="scss" scoped>
$color: #fff;
.footer {
  background: #060612;
  :deep(.app-content) {
    padding-bottom: 0;
  }
  .cookie-privacy {
    line-height: 48px;
    width: 100%;
    height: 48px;
    background-color: #060612;
    color: var(--o-color-text3);
    font-size: 14px;
    display: flex;
    justify-content: center;
    align-items: center;
    position: fixed;
    bottom: 0;
    right: 0;
    left: 0;
    z-index: 999;
    box-shadow: var(--o-shadow-l1);
    text-align: center;
    &.ru {
      line-height: 16px;
      display: inline-block;
      padding: 4px 0;
    }
    @media screen and (max-width: 1000px) {
      font-size: 12px;
      line-height: 20px;
      display: inline-block;
      &.ru {
        line-height: 10px;
        height: auto;
      }
    }
    a {
      cursor: pointer;
      text-decoration: solid;
      white-space: pre;
    }
    .icon {
      cursor: pointer;
      vertical-align: middle;
      margin-left: 16px;
      width: 24px;
      height: 24px;
      background: var(--o-color-greyblack3);
      border-radius: 50%;
      display: inline-flex;
      justify-content: center;
      align-items: center;
      svg {
        font-size: 20px;
        color: var(--el-color-white);
      }
      @media screen and (max-width: 1000px) {
        width: 20px;
        height: 20px;
        margin-left: 12px;
      }
    }
  }
  .atom {
    text-align: center;
    padding: var(--o-spacing-h3) 0 var(--o-spacing-h4);
    position: relative;
    border-bottom: 1px solid rgba(229, 229, 229, 0.12);
    @media (max-width: 1440px) {
      padding: var(--o-spacing-h4) 0;
    }

    &-text {
      font-size: var(--o-font-size-h6);
      font-weight: 400;
      color: $color;
      line-height: var(--o-line-height-h6);
      @media (max-width: 1440px) {
        font-size: var(--o-font-size-text);
        line-height: var(--o-line-height-text);
      }
    }
    &-logo {
      height: 40px;
      margin-top: 16px;
      @media (max-width: 1100px) {
        height: 30px;
      }
    }
  }

  &-content {
    background: url(../assets/footer/footer-bg.png) no-repeat bottom center;
    @media (max-width: 767px) {
      background: url(../assets/footer/footer-bg-mo.png) no-repeat bottom center;
    }
    .inner {
      display: flex;
      align-items: end;
      justify-content: space-between;
      padding: 18px 0 32px;
      position: relative;
      min-height: 118px;
      @media (max-width: 1400px) {
        padding: var(--o-spacing-h4) 0;
        flex-direction: column;
        justify-content: space-between;
        align-items: center;
      }
    }
  }
  &-logo {
    flex: 1;
    img {
      height: 46px;
    }
    .show-pc {
      display: block;
    }
    .show-mo {
      display: none;
    }
    @media (max-width: 1400px) {
      text-align: center;
      margin: 16px 0;
      .show-pc {
        display: none;
      }
      .show-mo {
        display: inline-block;
        height: 20px;
      }
    }
  }

  .copyright {
    font-size: var(--o-font-size-text);
    color: $color;
    margin-top: var(--o-spacing-h5);
    @media (max-width: 1400px) {
      font-size: var(--o-font-size-tip);
      line-height: var(--o-line-height-tip);
      margin-top: var(--o-spacing-h8);
    }
  }

  .footer-option {
    text-align: center;
    .link {
      color: $color;
      font-size: var(--o-font-size-text);
      display: inline-block;
      padding: 0 var(--o-spacing-h6);
      border-right: 1px solid $color;
      &:last-child {
        border-right: 0;
      }
      @media (max-width: 1400px) {
        font-size: var(--o-font-size-tip);
        line-height: var(--o-line-height-tip);
        padding: 0 var(--o-spacing-h9);
      }
    }
    @media (max-width: 1400px) {
      order: -1;
    }
  }

  .footer-right {
    flex: 1;
    .code-box {
      display: flex;
      justify-content: right;
      gap: 16px;
      margin-bottom: 16px;
      .code-pop {
        position: relative;
        height: 20px;
        display: block;
        > img {
          height: 100%;
          object-fit: cover;
        }
        .code-layer {
          position: absolute;
          top: -105px;
          left: -32px;
          z-index: 99;
          display: none;
          background: #fff;
          padding: 6px;
          img {
            width: 78px;
            height: 78px;
          }
          .txt {
            font-size: 12px;
            color: $color;
            display: none;
          }
          &::after {
            border: 10px solid transparent;
            content: '';
            border-top-color: #fff;
            position: absolute;
            bottom: -20px;
            left: 50%;
            transform: translateX(-50%);
            display: block;
          }
          @media (max-width: 800px) {
            display: block;
            position: initial;
            background: none;
            padding: 0;
            text-align: center;
            &::after {
              display: none !important;
            }
            .txt {
              display: block;
            }
          }
        }
        &:hover {
          .code-layer {
            display: block;
          }
        }
        @media (max-width: 800px) {
          height: auto;
          > img {
            display: none;
          }
        }
      }
      @media (max-width: 1400px) {
        justify-content: center;
      }
      @media (max-width: 1100px) {
        margin-top: 24px;
      }
    }
    .footer-links {
      display: flex;
      justify-content: right;
      align-items: center;
      gap: 16px;
      .links-logo {
        height: 16px;
        img {
          height: 100%;
          object-fit: cover;
        }
      }
      @media (max-width: 1100px) {
        justify-content: center;
      }
      @media (max-width: 800px) {
        display: flex;
        text-align: center;
        .img {
          height: 16px;
        }
      }
      &.iszh {
        gap: 10px;
        .links-logo {
          height: 14px;

          &:first-child {
            height: 18px;
          }
        }
        @media (max-width: 800px) {
          display: grid;
          grid-template-columns: repeat(3, 1fr);
          text-align: center;
          margin-top: 40px;
          .img {
            height: 16px;
          }
        }
      }
    }

    p {
      color: $color;
      font-size: var(--o-font-size-tip);
      margin-top: var(--o-spacing-h8);
    }
  }

  .email {
    color: $color;
    font-size: var(--o-font-size-text);
    @media (max-width: 1400px) {
      font-size: var(--o-font-size-tip);
    }
  }
}
</style>
