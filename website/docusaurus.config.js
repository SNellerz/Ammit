/** @type {import('@docusaurus/types').Config} */
const config = {
  title: 'ammit',
  tagline: 'Weigh every container. Devour the unworthy.',
  favicon: 'img/branding/ammit-wordmark.svg',

  url: 'https://snellerz.github.io',
  baseUrl: '/Ammit/',

  organizationName: 'SNellerz',
  projectName: 'Ammit',

  onBrokenLinks: 'throw',
  markdown: {
    hooks: {
      onBrokenMarkdownLinks: 'warn'
    }
  },
  i18n: {
    defaultLocale: 'en',
    locales: ['en']
  },

  presets: [
    [
      'classic',
      /** @type {import('@docusaurus/preset-classic').Options} */
      ({
        docs: {
          sidebarPath: require.resolve('./sidebars.js'),
          routeBasePath: '/'
        },
        blog: false,
        theme: {
          customCss: require.resolve('./src/css/custom.css')
        }
      })
    ]
  ],

  themeConfig:
    /** @type {import('@docusaurus/preset-classic').ThemeConfig} */
    ({
      image: 'img/branding/ammit-wordmark.svg',
      navbar: {
        title: 'ammit',
        logo: {
          alt: 'ammit logo',
          src: 'img/branding/ammit-wordmark.svg'
        },
        items: [
          {
            type: 'docSidebar',
            sidebarId: 'tutorialSidebar',
            position: 'left',
            label: 'Docs'
          },
          {
            href: 'https://github.com/SNellerz/Ammit',
            label: 'GitHub',
            position: 'right'
          }
        ]
      },
      footer: {
        style: 'dark',
        links: [
          {
            title: 'Docs',
            items: [
              {
                label: 'Overview',
                to: '/'
              },
              {
                label: 'Command Reference',
                to: '/commands'
              }
            ]
          },
          {
            title: 'Community',
            items: [
              {
                label: 'GitHub Issues',
                href: 'https://github.com/SNellerz/Ammit/issues'
              }
            ]
          },
          {
            title: 'More',
            items: [
              {
                label: 'Repository',
                href: 'https://github.com/SNellerz/Ammit'
              }
            ]
          }
        ],
        copyright: `Copyright ${new Date().getFullYear()} ammit`
      }
    })
};

module.exports = config;
