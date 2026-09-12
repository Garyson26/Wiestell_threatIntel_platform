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

// --- Content Signals ---------------------------------------------------------
//
// `Content-Signal` declares how this site's content may be used, on three axes:
// `search` (traditional indexing), `ai-input` (retrieval at answer time, e.g.
// RAG) and `ai-train` (training or fine-tuning a model).
//
// DRAFT, AND NOT LOAD-BEARING. The vocabulary comes from
// draft-romm-aipref-contentsignals, an IETF Internet-Draft that EXPIRED in April
// 2026 without ever being adopted by a working group; the push behind it is
// Cloudflare's, not the IETF's. Google has stated publicly that the directive
// has no effect on any of its crawlers, and no major crawler or model provider
// is known to honour it. Read this as a published statement of preference --
// worth something if the vocabulary is ever enforced, and evidence of intent in
// the meantime -- and not as access control. The server-side guards in
// backend/app/api/__init__.py remain the only thing protecting anything.
//
// Values are an owner decision (handoff spec 9, 2026-09-12), not a default:
//   search=yes    Discoverability is the whole point of a free public platform.
//   ai-input=yes  An agent looking up an indicator and reading the answer IS the
//                 use case. Saying no here would contradict the product.
//   ai-train=no   The corpus is aggregated from public feeds, so there is less
//                 to protect than a publisher would have -- but the scoring,
//                 enrichment and correlation are original work. Conservative on
//                 purpose: this can be loosened later, the reverse is harder.
//
// Cloudflare added a fourth field, `use`, in July 2026. Deliberately omitted: it
// is a single-vendor extension layered on an already-expired vocabulary, and
// re-editing one line later is cheaper than publishing a semantic we are not
// yet sure of.
const CONTENT_SIGNAL = 'search=yes, ai-train=no, ai-input=yes';

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
    // next-sitemap's policy objects understand only userAgent / allow / disallow
    // / crawlDelay -- see IRobotPolicy in its type definitions, and
    // RobotsTxtBuilder.generateRobotsTxt, which reads those four keys and no
    // others. An extra key on a policy is dropped SILENTLY, so `Content-Signal`
    // cannot be expressed as a policy field and has to be spliced in here.
    //
    // Per the Content Signals format the directive belongs INSIDE a user-agent
    // group, so it goes directly beneath `User-agent: *`. Prepended to the top
    // of the file instead it would sit outside every group and apply to none.
    transformRobotsTxt: async (_config, robotsTxt) => {
      const anchor = 'User-agent: *\n';
      if (!robotsTxt.includes(anchor)) {
        // Fail the build rather than ship a robots.txt that has quietly lost the
        // signal. The only way to get here is next-sitemap changing the shape of
        // the group header, which is a one-line fix -- and far better found at
        // build time than months later from a scan.
        throw new Error(
          'next-sitemap: no "User-agent: *" group in the generated robots.txt, ' +
            'so Content-Signal was not inserted. Check RobotsTxtBuilder output ' +
            'against next-sitemap.config.js after upgrading next-sitemap.'
        );
      }
      return robotsTxt.replace(
        anchor,
        `${anchor}Content-Signal: ${CONTENT_SIGNAL}\n`
      );
    },
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
