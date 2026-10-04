import { defineConfig } from 'vitepress'

const base = '/nsc-filehouse/'

const guideSidebar = [
  {
    text: 'Guide',
    items: [
      { text: 'Getting started', link: '/guide/getting-started' },
      { text: 'Uploads and downloads', link: '/guide/uploads' },
      { text: 'Permissions', link: '/guide/permissions' }
    ]
  }
]

const apiSidebar = [
  {
    text: 'API Reference',
    items: [
      { text: 'Overview', link: '/api/overview' },
      {
        text: 'Reference',
        items: [
          { text: 'System', link: '/api/reference/system' },
          { text: 'Buckets', link: '/api/reference/buckets' },
          { text: 'Objects', link: '/api/reference/objects' },
          { text: 'Uploads', link: '/api/reference/uploads' },
          { text: 'Presign', link: '/api/reference/presign' },
          { text: 'Self-service', link: '/api/reference/self-service' },
          { text: 'Admin', link: '/api/reference/admin' }
        ]
      },
      { text: 'Download OpenAPI 3.1 specification', link: `${base}openapi.yaml` }
    ]
  }
]

const serviceSidebar = [
  {
    text: 'Operations',
    items: [
      { text: 'Deployment', link: '/deployment' },
      { text: 'Manual', link: '/manual' }
    ]
  }
]

export default defineConfig({
  title: 'Filehouse',
  description: 'Object storage microservice',
  base,
  cleanUrls: true,
  lastUpdated: true,
  themeConfig: {
    nav: [
      { text: 'Guide', link: '/guide/getting-started' },
      { text: 'API Reference', link: '/api/overview' },
      {
        text: 'GitHub',
        link: 'https://github.com/crazy4chicken/nsc-filehouse'
      }
    ],
    sidebar: {
      '/guide/': guideSidebar,
      '/api/': apiSidebar,
      '/deployment': serviceSidebar,
      '/manual': serviceSidebar
    },
    search: {
      provider: 'local'
    }
  }
})
