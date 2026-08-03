import { NextRequest, NextResponse } from 'next/server';

/**
 * CSP violation report sink.
 *
 * Reachable at /api/csp-report even though next.config.js rewrites /api/* to the
 * FastAPI backend: rewrites returned as a plain array are applied *after*
 * filesystem routes, so this route handler takes precedence.
 *
 * Browsers post reports unauthenticated and cross-process, so treat the body as
 * untrusted: cap it, log a fixed set of fields rather than the whole document,
 * and never echo it back.
 */

// A CSP report is a few hundred bytes. Anything larger is not a real report.
const MAX_BODY_BYTES = 8 * 1024;

// Only these fields are logged. `script-sample` is deliberately excluded — it
// contains a fragment of the blocked script, which for an inline handler can
// include page data.
const REPORTED_FIELDS = [
  'document-uri',
  'violated-directive',
  'effective-directive',
  'blocked-uri',
  'disposition',
  'status-code',
] as const;

function truncate(value: unknown, max = 300): string | undefined {
  if (typeof value !== 'string' || !value) return undefined;
  return value.length > max ? `${value.slice(0, max)}...` : value;
}

export async function POST(req: NextRequest) {
  const raw = await req.text().catch(() => '');

  if (!raw || raw.length > MAX_BODY_BYTES) {
    // 204 regardless: a report sink must not become a probe oracle.
    return new NextResponse(null, { status: 204 });
  }

  try {
    const parsed = JSON.parse(raw);
    // report-uri wraps the payload in `csp-report`; the Reporting API (report-to)
    // posts an array of `{ type, body }` envelopes instead.
    const report = parsed?.['csp-report'] ?? parsed?.[0]?.body ?? parsed;

    const summary: Record<string, string> = {};
    for (const field of REPORTED_FIELDS) {
      const value = truncate(report?.[field]);
      if (value) summary[field] = value;
    }

    console.warn('[csp-violation]', JSON.stringify(summary));
  } catch {
    console.warn('[csp-violation] unparseable report body');
  }

  return new NextResponse(null, { status: 204 });
}
