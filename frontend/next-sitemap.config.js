/** @type {import('next-sitemap').IConfig} */

// Only the public marketing surface belongs in the sitemap. Everything else is
// behind authentication.
//
// This exclusion used to be implicit: next-sitemap enumerates every generated
// route, so `/dashboard`, `/settings`, `/ai-assistant`, `/analytics`,
// `/ioc-search` and the rest were all declared publicly indexable, and
// `/reset-password` was advertised alongside them. Pre-existing — not introduced
// by the route-group refactor, which only moved the marketing pages.
//
// Declaring an authenticated route in a sitemap does not grant access to it: the
// server-side guards in backend/app/api/__init__.py are what protect the data.
// What it does do is invite crawlers to request pages that can only ever return a
// login redirect, publish the app's internal route structure to anyone who reads
// sitemap.xml, and put those URLs in search results where a user may land on them
// expecting content.
//
// Keep this in step with the route groups under src/app/: everything in
// (protected), (analytics) and (bare) is excluded; only (marketing) is listed.
const AUTHENTICATED_ROUTES = [
  // (protected)
  '/ai-assistant',
  '/attack-map',
  '/contacts',
  '/dashboard',
  '/feeds',
  '/hunting',
  '/ioc',
  '/my-profile',
  '/profile',
  '/reports',
  '/settings',
  // (analytics)
  '/analytics',
  '/history',
  '/ioc-detail',
  '/ioc-search',
  '/submit',
  // (bare) — auth pages. /login and /signup are excluded deliberately too: they
  // are entry points rather than content, and /forgot-password and
  // /reset-password should never appear in a search result.
  '/forgot-password',
  '/login',
  '/plateform-pilot',
  '/reset-password',
  '/signup',
];

// Wildcards so dynamic children (/ioc/<uuid>, /ioc-detail/<uuid>) are covered too.
const EXCLUDE = [
  '/api/*',
  ...AUTHENTICATED_ROUTES,
  ...AUTHENTICATED_ROUTES.map((route) => `${route}/*`),
];

module.exports = {
  siteUrl: 'https://wiestell.com',
  generateRobotsTxt: true,
  sitemapSize: 5000,
  robotsTxtOptions: {
    policies: [
      {
        userAgent: '*',
        allow: '/',
        // Mirrors EXCLUDE. next-sitemap does not derive robots.txt policies from
        // `exclude`, so both lists have to be maintained — omitting a route here
        // leaves it crawlable even though it is absent from the sitemap.
        disallow: ['/api/', ...AUTHENTICATED_ROUTES],
      },
    ],
  },
  exclude: EXCLUDE,
  generateIndexSitemap: false,
  changefreq: 'daily',
  priority: 0.7,
  // Add any dynamic PUBLIC routes here if needed. Do not add authenticated ones.
  additionalPaths: async (config) => {
    const result = [];
    return result;
  },
};
