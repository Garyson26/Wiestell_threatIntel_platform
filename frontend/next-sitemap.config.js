/** @type {import('next-sitemap').IConfig} */
module.exports = {
  siteUrl: 'https://wiestell.com',
  generateRobotsTxt: true,
  robotsTxtOptions: {
    policies: [
      {
        userAgent: '*',
        allow: '/',
      },
    ],
  },
  // Optional: Add any paths you want to exclude
  exclude: ['/api/*', '/admin/*'],
  // Optional: Generate index sitemaps
  generateIndexSitemap: false,
  // Optional: Change the priority or frequency
  changefreq: 'daily',
  priority: 0.7,
  // Optional: Additional paths that might not be discovered by crawling
  additionalPaths: async (config) => {
    const result = [];
    // Add any dynamic routes here if needed
    // result.push({ loc: '/custom-page', priority: 0.8, changefreq: 'weekly' });
    return result;
  },
};
