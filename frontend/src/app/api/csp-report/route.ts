import { NextRequest, NextResponse } from 'next/server';
import { noCorsHeaders } from '@/lib/cors';

/**
 * CSP Violation Report Endpoint
 * 
 * Receives Content-Security-Policy violation reports from the browser.
 * This is an internal endpoint - should only accept reports from wiestell.com pages.
 */

export async function OPTIONS() {
  // Handle preflight CORS request
  return new NextResponse(null, {
    status: 204,
    headers: noCorsHeaders,
  });
}

export async function POST(req: NextRequest) {
  const body = await req.json().catch(() => ({}));
  
  // Log violation details
  console.error('[CSP Violation]', JSON.stringify(body, null, 2));
  
  // Optionally forward to Sentry / Datadog / your logging service
  // Example:
  // if (process.env.SENTRY_DSN) {
  //   Sentry.captureMessage('CSP Violation', {
  //     level: 'warning',
  //     extra: body
  //   });
  // }
  
  return new NextResponse(null, { 
    status: 204,
    headers: noCorsHeaders,
  });
}
