/** @type {import('next').NextConfig} */

// Third-party origins the application actually loads. Enumerated rather than
// allowing "https:" wholesale: with script-src permitting 'unsafe-inline' and the
// session token held in localStorage, a blanket connect-src/img-src is a direct
// exfiltration channel for injected script.
const GTM = 'https://www.googletagmanager.com';                 // GTM + gtag.js
const GA = [                                                     // GA4 collect beacons
  'https://www.google-analytics.com',
  'https://*.google-analytics.com',
  'https://*.analytics.google.com',
  'https://stats.g.doubleclick.net',
  'https://*.g.doubleclick.net',
].join(' ');
const GOOGLE_FONTS_CSS = 'https://fonts.googleapis.com';         // @import in globals.css
const GOOGLE_FONTS_FILES = 'https://fonts.gstatic.com';

// API traffic is same-origin: lib/api.ts uses relative paths and next.config
// rewrites /api/* to the backend server-side, so the browser never opens a
// cross-origin connection to it. 'self' is therefore sufficient for connect-src.
//
// Two policies, because analytics is scoped to one route group.
// app/(marketing)/layout.tsx is the only layout that loads GTM and gtag —
// gtag reports `page_location` including the query string, and the signed-in app
// puts indicator values there (`/ioc-search?q=`, `/ioc?search=`). The app policy
// therefore names no Google origin at all, so even injected script cannot reach
// them; the marketing policy allows exactly what those three pages load.
//
// The two `source` patterns below MUST stay mutually exclusive. Next.js appends
// headers from every matching rule, so an overlap emits two Content-Security-Policy
// headers and the browser enforces the intersection — which is neither policy.
const MARKETING_PATHS = ['/', '/about', '/contact'];

function buildCSP({ analytics }) {
  return [
    "default-src 'self'",
    // 'unsafe-inline' is required for the JSON-LD tag in app/layout.tsx, the
    // inline GTM bootstrap and gtag config on marketing pages, and Next's own
    // hydration payload. See SECURITY_REVIEW.md H-07 for why nonces are not used.
    `script-src 'self' 'unsafe-inline'${analytics ? ` ${GTM}` : ''}`,
    `style-src 'self' 'unsafe-inline' ${GOOGLE_FONTS_CSS}`,
    `img-src 'self' data:${analytics ? ` ${GTM} ${GA}` : ''}`,
    `font-src 'self' ${GOOGLE_FONTS_FILES}`,
    `connect-src 'self'${analytics ? ` ${GTM} ${GA}` : ''}`,
    // GTM <noscript> iframe, in app/(marketing)/layout.tsx only.
    analytics ? `frame-src ${GTM}` : "frame-src 'none'",
    "object-src 'none'",
    "frame-ancestors 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    // report-uri is deprecated but still the only directive Safari honours;
    // report-to is the Reporting API replacement. Both point at the Next route
    // handler at app/api/csp-report/route.ts, which wins over the /api/* rewrite
    // because rewrites returned as a plain array are applied after filesystem routes.
    'report-uri /api/csp-report',
    'report-to csp-endpoint',
  ].join('; ');
}

const CSP_MARKETING = buildCSP({ analytics: true });
const CSP_APP = buildCSP({ analytics: false });

const nextConfig = {
  reactStrictMode: true,
  // Do not advertise the framework version in responses
  poweredByHeader: false,
  // output: 'standalone', // Removed - incompatible with Cloudflare Pages
  async headers() {
    // Everything except /api/* and the marketing paths. `.+` rather than `.*` so
    // the bare `/` does not match here — it belongs to the marketing rule, and an
    // overlap would emit two CSP headers.
    const APP_SOURCE = '/((?!api/|about$|contact$).+)';

    const commonHeaders = (csp) => [
          {
            key: 'Reporting-Endpoints',
            value: 'csp-endpoint="/api/csp-report"'
          },
          {
            key: 'Strict-Transport-Security',
            value: 'max-age=31536000; includeSubDomains; preload'
          },
          {
            // Enforced, not report-only: a report-only policy blocks nothing.
            key: 'Content-Security-Policy',
            value: csp
          },
          {
            key: 'X-Content-Type-Options',
            value: 'nosniff'
          },
          {
            key: 'X-Frame-Options',
            value: 'DENY'
          },
          {
            key: 'Referrer-Policy',
            value: 'strict-origin-when-cross-origin'
          },
          {
            key: 'Permissions-Policy',
            value: 'camera=(), microphone=(), geolocation=(), interest-cohort=(), payment=(), usb=(), bluetooth=(), magnetometer=(), gyroscope=(), accelerometer=(), ambient-light-sensor=(), autoplay=(), encrypted-media=(), picture-in-picture=()'
          },
          {
            key: 'Cross-Origin-Opener-Policy',
            value: 'same-origin-allow-popups'
          },
          {
            // 'cross-origin' is the value that opts OUT of CORP. This dashboard
            // serves no assets to third parties, so same-origin is correct.
            key: 'Cross-Origin-Resource-Policy',
            value: 'same-origin'
          },
          {
            key: 'X-Powered-By',
            value: ''
          }
    ];

    return [
      // The signed-in app plus every other non-API route. Names no Google origin,
      // so analytics cannot load here even if a tag were added to a layout by
      // mistake — CSP is the backstop for the route-group scoping.
      { source: APP_SOURCE, headers: commonHeaders(CSP_APP) },
      // Public marketing pages, which do load GTM and gtag.
      ...MARKETING_PATHS.map((source) => ({
        source,
        headers: commonHeaders(CSP_MARKETING),
      })),
    ];
  },
  async redirects() {
    return [
      {
        source: '/:path*',
        has: [
          {
            type: 'host',
            value: 'www.wiestell.com',
          },
        ],
        destination: 'https://wiestell.com/:path*',
        permanent: true,
      },
    ];
  },
  async rewrites() {
    return [
      {
        source: '/api/:path*',
        // Fallback only. NEXT_PUBLIC_API_URL is set in the Vercel dashboard and wins.
        // Updated 2026-08-17 at cutover: the old origin is dead, so an unset env
        // var would have silently proxied to nothing.
        destination: `${process.env.NEXT_PUBLIC_API_URL || 'https://wiestell-backend.onrender.com'}/api/:path*`,
      },
    ];
  },
};

module.exports = nextConfig;
