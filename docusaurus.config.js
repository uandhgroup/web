// @ts-check
// Note: type annotations allow type checking and IDEs autocompletion

const prismReact = require('prism-react-renderer');

/** @type {import('@docusaurus/types').Config} */
const config = {
  title: 'Terser',
  tagline: 'JavaScript mangler and compressor toolkit',
  favicon: 'img/favicon.ico',

  // Set the production url of your site here
  url: 'https://tech-docs.hhf.co.in',
  // Set the /<baseUrl>/ pathname under which your site is served
  // For GitHub pages deployment, it is often '/<projectName>/'
  baseUrl: '/',
  trailingSlash: true,

  // GitHub pages deployment config.
  // If you aren't using GitHub pages, you don't need these.
  // organizationName: 'hhf', // Usually your GitHub org/user name.
  // projectName: 'hhf.github.io', // Usually your repo name.
  // deploymentBranch: 'master', // Branch used to deploy on GitHub pages.

  onBrokenLinks: 'throw',
  onBrokenMarkdownLinks: 'warn',

  // Even if you don't use internalization, you can use this field to set useful
  // metadata like html lang. For example, if your site is Chinese, you may want
  // to replace "en" with "zh-Hans".
  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  presets: [
    [
      'classic',
      /** @type {import('@docusaurus/preset-classic').Options} */
      ({
        docs: {
          sidebarPath: require.resolve('./sidebars.js'),
          path: './docs',
          // Please change this to your repo.
          // Remove this to remove the "edit this page" links.
          // editUrl:
          //  'https://github.com/terser/terser-website/tree/master/packages/create-docusaurus/templates/shared/',
        },
        blog: {
          showReadingTime: true,
          // Please change this to your repo.
          // Remove this to remove the "edit this page" links.
          // editUrl:
          //  'https://github.com/terser/terser-website/tree/master/packages/create-docusaurus/templates/shared/',
        },
        theme: {
          customCss: require.resolve('./src/css/custom.css'),
        },
      }),
    ],
  ],

  themeConfig:
    /** @type {import('@docusaurus/preset-classic').ThemeConfig} */
    ({
      image: 'img/terser-square-logo.png',
      navbar: {
        title: 'Terser',
        logo: {
          alt: 'Terser logo',
          src: 'img/terser-square-logo.svg',
          height: 32,
          width: 32,
        },
        items: [
          {
            label: 'API Docs',
            type: 'doc',
            docId: 'api-reference',
            position: 'left',
          },
          {
            label: 'CLI Docs',
            type: 'doc',
            docId: 'cli-usage',
            position: 'left',
          },
          {
            label: 'Options',
            type: 'doc',
            docId: 'options',
            position: 'left',
          },
          {
            label: 'Nginx',
            type: 'doc',
            docId: 'nginx',
            position: 'left',
          },
          {
            href: 'https://try.terser.org',
            label: 'REPL',
            position: 'right',
          },
          {
            href: 'https://github.com/terser/terser',
            label: 'GitHub',
            position: 'right',
          },
          {
            href: 'https://opencollective.com/terser',
            label: 'Donate',
            position: 'right',
          },
        ],
      },
      footer: {
        style: 'dark',
        links: [
          {
            title: 'Docs',
            items: [
              {
                label: 'CLI Usage',
                to: '/docs/cli-usage',
              },
              {
                label: 'API Reference',
                to: '/docs/api-reference',
              },
            ],
          },
          {
            title: 'Community',
            items: [
              {
                label: 'Stack Overflow',
                href: 'https://stackoverflow.com/questions/tagged/terser',
              },
            ],
          },
          {
            title: 'More',
            items: [
              {
                label: 'Blog',
                to: '/blog',
              },
              {
                label: 'GitHub',
                href: 'https://github.com/terser/terser',
              },
            ],
          },
        ],
        copyright: `Copyright © ${new Date().getFullYear()} terser.org. Built with Docusaurus.`,
      },
      prism: {
        theme: prismReact.themes.github,
        darkTheme: prismReact.themes.dracula,
      },
      algolia: {
        appId: 'N8MO33ENBY',
        apiKey: '8ecfec7006145ef2530a9a241ee01fbb',
        indexName: 'terser3',
        contextualSearch: false,
      },
    }),
};

module.exports = config;
