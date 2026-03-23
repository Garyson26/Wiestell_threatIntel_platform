/**
 * CORS Configuration for API Routes
 * 
 * Security headers for Next.js API routes to restrict cross-origin access.
 * Use these headers for any endpoint that handles non-public or sensitive data.
 */

/**
 * Strict CORS headers - only allow requests from wiestell.com
 * Use for authenticated endpoints or sensitive data
 */
export const strictCorsHeaders = {
  'Access-Control-Allow-Origin': 'https://wiestell.com',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Access-Control-Allow-Credentials': 'true',
};

/**
 * Public CORS headers - allow any HTTPS origin
 * Use only for truly public, read-only endpoints with no authentication
 */
export const publicCorsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

/**
 * Internal-only - no CORS (same-origin only)
 * Use for endpoints that should only be called by the same domain
 */
export const noCorsHeaders = {
  'Access-Control-Allow-Origin': 'https://wiestell.com',
  'Access-Control-Allow-Methods': 'POST',
  'Access-Control-Allow-Headers': 'Content-Type',
};

/**
 * Helper function to add CORS headers to a NextResponse
 */
export function withCors(
  response: Response,
  headers: Record<string, string> = strictCorsHeaders
): Response {
  Object.entries(headers).forEach(([key, value]) => {
    response.headers.set(key, value);
  });
  return response;
}
