import DefaultTheme from 'vitepress/theme'
import type { Theme } from 'vitepress'
import ConfigBuilder from './builder/ConfigBuilder.vue'
import './custom.css'

export default {
  extends: DefaultTheme,
  enhanceApp({ app }) {
    app.component('ConfigBuilder', ConfigBuilder)
  }
} satisfies Theme
