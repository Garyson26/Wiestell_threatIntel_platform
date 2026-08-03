import Script from 'next/script';

/**
 * Layout for the public marketing pages — `/`, `/about`, `/contact`.
 *
 * This is the ONLY place Google Tag Manager and gtag.js load. They used to sit in
 * the root layout, which meant they loaded on every route including the signed-in
 * app — and gtag reports `page_location` including the query string. The app puts
 * indicator values in query strings:
 *
 *   - `/ioc-search?q=<indicator>`  (landing page search, global header search)
 *   - `/ioc?search=<url>`
 *
 * so an analyst's investigation targets were being sent to Google. Referrer-Policy
 * does not mitigate this: gtag transmits the URL inside its own payload rather
 * than as a Referer header.
 *
 * Route-group scoping is deliberate. A pathname allowlist would depend on every
 * future route remembering to stay off it; this way `(protected)`, `(analytics)`
 * and `(bare)` cannot inherit analytics at all. `(bare)` is excluded on purpose —
 * it holds the auth pages, where the password-reset flow handles email addresses.
 *
 * If you need a tag on the signed-in app, strip the query string before the
 * pageview and say so here — do not move this back to the root layout.
 */
export default function MarketingLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <>
      {/* Google Tag Manager */}
      <Script id="gtm-loader" strategy="afterInteractive">
        {`(function(w,d,s,l,i){w[l]=w[l]||[];w[l].push({'gtm.start':
new Date().getTime(),event:'gtm.js'});var f=d.getElementsByTagName(s)[0],
j=d.createElement(s),dl=l!='dataLayer'?'&l='+l:'';j.async=true;j.src=
'https://www.googletagmanager.com/gtm.js?id='+i+dl;f.parentNode.insertBefore(j,f);
})(window,document,'script','dataLayer','GTM-TXF68KRQ');`}
      </Script>

      {/* Google tag (gtag.js) */}
      <Script
        src="https://www.googletagmanager.com/gtag/js?id=G-FG3RH76R6J"
        strategy="afterInteractive"
      />
      <Script id="gtag-config" strategy="afterInteractive">
        {`window.dataLayer = window.dataLayer || [];
function gtag(){dataLayer.push(arguments);}
gtag('js', new Date());
gtag('config', 'G-FG3RH76R6J');`}
      </Script>

      {/* Google Tag Manager (noscript) */}
      <noscript>
        <iframe
          src="https://www.googletagmanager.com/ns.html?id=GTM-TXF68KRQ"
          height="0"
          width="0"
          style={{ display: 'none', visibility: 'hidden' }}
        />
      </noscript>

      {children}
    </>
  );
}
