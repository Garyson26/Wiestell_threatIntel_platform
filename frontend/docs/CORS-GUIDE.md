# CORS Configuration Guide for API Routes

This document explains how to implement proper CORS headers for Next.js API routes in the Wiestell platform.

## Overview

CORS (Cross-Origin Resource Sharing) controls which domains can access your API routes from a browser. The wildcard `*` allows any website to call your endpoints, which is a security risk for authenticated or sensitive data.

## Available CORS Configurations

Located in: [`frontend/src/lib/cors.ts`](../src/lib/cors.ts)

### 1. Strict CORS (Recommended Default)

**Use for:** Authenticated endpoints, user-specific data, any sensitive operations

```typescript
import { NextRequest, NextResponse } from 'next/server';
import { strictCorsHeaders } from '@/lib/cors';

export async function GET(req: NextRequest) {
  const data = await getSensitiveData();
  
  return NextResponse.json(data, {
    headers: strictCorsHeaders,
  });
}

export async function OPTIONS() {
  return new NextResponse(null, {
    status: 204,
    headers: strictCorsHeaders,
  });
}
```

**Allows:**
- Origin: `https://wiestell.com` only
- Methods: `GET, POST, OPTIONS`
- Headers: `Content-Type, Authorization`
- Credentials: Yes (cookies, auth tokens)

### 2. Internal-Only (Same-Origin)

**Use for:** Internal endpoints like CSP reporting, webhooks, background jobs

```typescript
import { NextRequest, NextResponse } from 'next/server';
import { noCorsHeaders } from '@/lib/cors';

export async function POST(req: NextRequest) {
  // Process internal request
  
  return new NextResponse(null, {
    status: 204,
    headers: noCorsHeaders,
  });
}
```

**Allows:**
- Origin: `https://wiestell.com` only
- Methods: `POST` only
- No credentials

### 3. Public CORS (Use Sparingly)

**Use for:** Truly public, read-only data with NO authentication required

```typescript
import { NextRequest, NextResponse } from 'next/server';
import { publicCorsHeaders } from '@/lib/cors';

export async function GET(req: NextRequest) {
  const publicData = await getPublicThreatFeed();
  
  return NextResponse.json(publicData, {
    headers: publicCorsHeaders,
  });
}
```

**Allows:**
- Origin: `*` (any domain)
- Methods: `GET, OPTIONS` only
- No credentials

⚠️ **Warning:** Only use for endpoints that require NO authentication and contain NO sensitive data.

## Real-World Examples

### Example 1: IOC Lookup (Authenticated)

```typescript
// app/api/ioc/lookup/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { strictCorsHeaders } from '@/lib/cors';

export async function OPTIONS() {
  return new NextResponse(null, { status: 204, headers: strictCorsHeaders });
}

export async function POST(req: NextRequest) {
  // Verify authentication
  const token = req.headers.get('authorization');
  if (!token) {
    return NextResponse.json(
      { error: 'Unauthorized' },
      { status: 401, headers: strictCorsHeaders }
    );
  }
  
  const body = await req.json();
  const results = await searchIOC(body.indicator);
  
  return NextResponse.json(results, { headers: strictCorsHeaders });
}
```

### Example 2: Public Threat Feed (Read-Only)

```typescript
// app/api/public/feeds/latest/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { publicCorsHeaders } from '@/lib/cors';

export async function OPTIONS() {
  return new NextResponse(null, { status: 204, headers: publicCorsHeaders });
}

export async function GET() {
  const feeds = await getLatestPublicFeeds();
  
  return NextResponse.json(feeds, { headers: publicCorsHeaders });
}
```

### Example 3: CSP Violation Reporting (Internal)

Already implemented in [`app/api/csp-report/route.ts`](../src/app/api/csp-report/route.ts)

```typescript
import { NextRequest, NextResponse } from 'next/server';
import { noCorsHeaders } from '@/lib/cors';

export async function POST(req: NextRequest) {
  const body = await req.json().catch(() => ({}));
  console.error('[CSP Violation]', JSON.stringify(body, null, 2));
  
  return new NextResponse(null, { status: 204, headers: noCorsHeaders });
}
```

## Decision Tree: Which CORS Header to Use?

```
Does the endpoint require authentication?
├─ YES → Use strictCorsHeaders
└─ NO → Does it handle user-specific data?
    ├─ YES → Use strictCorsHeaders
    └─ NO → Is it meant for internal use only?
        ├─ YES → Use noCorsHeaders
        └─ NO → Is it truly public read-only data?
            ├─ YES → Use publicCorsHeaders
            └─ UNSURE → Use strictCorsHeaders (safer default)
```

## Testing CORS Configuration

### Test Strict CORS

```bash
# Should succeed from wiestell.com
curl -X POST https://wiestell.com/api/ioc/lookup \
  -H "Origin: https://wiestell.com" \
  -H "Content-Type: application/json" \
  -i

# Should fail from other origins
curl -X POST https://wiestell.com/api/ioc/lookup \
  -H "Origin: https://malicious-site.com" \
  -H "Content-Type: application/json" \
  -i
```

### Verify in Browser Console

```javascript
// Should succeed
fetch('https://wiestell.com/api/endpoint', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ data: 'test' })
})
.then(r => r.json())
.then(console.log);

// From another domain - should fail with CORS error
```

## Common Mistakes to Avoid

❌ **DON'T:**
```typescript
// Global wildcard CORS
'Access-Control-Allow-Origin': '*'
'Access-Control-Allow-Credentials': 'true'  // ← Security vulnerability!
```

❌ **DON'T:**
```typescript
// Forgetting OPTIONS handler
export async function POST() { /* ... */ }
// ← Browser preflight will fail without OPTIONS handler
```

✅ **DO:**
```typescript
// Specific origin + credentials when needed
'Access-Control-Allow-Origin': 'https://wiestell.com'
'Access-Control-Allow-Credentials': 'true'

// Always handle OPTIONS for POST/PUT/DELETE
export async function OPTIONS() { /* ... */ }
```

## Security Best Practices

1. **Default to Strict:** When in doubt, use `strictCorsHeaders`
2. **Never mix wildcard + credentials:** `*` with `Access-Control-Allow-Credentials` is a vulnerability
3. **Handle preflight:** Always implement `OPTIONS` handler for non-GET requests
4. **Validate origin:** For dynamic origins, validate from a whitelist
5. **Log suspicious requests:** Monitor for CORS errors in production

## Backend CORS Configuration

The FastAPI backend already has restricted CORS:

**File:** `backend/app/config.py`
```python
CORS_ORIGINS: str = "https://wiestell.com,https://www.wiestell.com"
```

This ensures the backend API only accepts requests from the frontend domain.

## Vercel Environment Variables

Ensure production environment has proper CORS configuration:

```bash
# Vercel Dashboard → Backend Project → Settings → Environment Variables
CORS_ORIGINS=https://wiestell.com,https://www.wiestell.com
```

## References

- [MDN: CORS](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)
- [OWASP: CORS Security](https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny)
- [Next.js API Routes](https://nextjs.org/docs/app/building-your-application/routing/route-handlers)

---

**Last Updated:** 23 March 2026  
**Maintained by:** Security Team
