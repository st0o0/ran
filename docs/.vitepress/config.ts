import { defineConfig } from 'vitepress'

export default defineConfig({
  base: '/ran/',
  lang: 'en',
  title: 'rán',
  description: 'Single-binary honeypot that pushes classified alerts to CrowdSec',
  themeConfig: {
    nav: [
      { text: 'Guide', link: '/getting-started' },
      { text: 'Traps', link: '/traps' },
      { text: 'Configuration', link: '/configuration' },
      { text: 'Config builder', link: '/builder' },
      { text: 'CrowdSec', link: '/crowdsec' },
      { text: 'Comparison', link: '/comparison' }
    ],
    sidebar: [
      {
        text: 'Guide',
        items: [
          { text: 'Getting started', link: '/getting-started' },
          { text: 'Traps', link: '/traps' },
          { text: 'Configuration', link: '/configuration' },
          { text: 'Config builder', link: '/builder' },
          { text: 'Classification and alerts', link: '/classification-and-alerts' },
          { text: 'CrowdSec', link: '/crowdsec' }
        ]
      },
      {
        text: 'Operations',
        items: [
          { text: 'Metrics', link: '/metrics' },
          { text: 'Log format', link: '/log-format' },
          { text: 'Hardening', link: '/hardening' },
          { text: 'Troubleshooting', link: '/troubleshooting' }
        ]
      },
      {
        text: 'Background',
        items: [
          { text: 'Comparison with alternatives', link: '/comparison' }
        ]
      }
    ],
    socialLinks: [
      { icon: 'github', link: 'https://github.com/st0o0/ran' }
    ],
    search: {
      provider: 'local'
    }
  }
})
