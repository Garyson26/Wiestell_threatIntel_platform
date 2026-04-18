#!/bin/bash
#
# Security Headers Verification Script
# Checks all security headers for wiestell.com
#
# Usage: ./verify-security-headers.sh [domain]
# Example: ./verify-security-headers.sh wiestell.com

set -e

DOMAIN="${1:-wiestell.com}"
BACKEND_DOMAIN="${2:-${BACKEND_URL:-wiestell-threatintel-platform.onrender.com}}"

echo "=================================================="
echo "Security Headers Verification for: $DOMAIN"
echo "Date: $(date)"
echo "=================================================="
echo ""

# Color codes
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Helper function to check if header exists
check_header() {
    local header_name="$1"
    local expected_value="$2"
    local result=$(curl -sI "https://$DOMAIN" | grep -i "^$header_name:" | cut -d' ' -f2-)
    
    if [ -z "$result" ]; then
        echo -e "${RED}✗${NC} $header_name: MISSING"
        return 1
    else
        result=$(echo "$result" | tr -d '\r\n')
        if [ -n "$expected_value" ]; then
            if [[ "$result" == *"$expected_value"* ]]; then
                echo -e "${GREEN}✓${NC} $header_name: $result"
                return 0
            else
                echo -e "${YELLOW}⚠${NC} $header_name: $result (expected: $expected_value)"
                return 1
            fi
        else
            echo -e "${GREEN}✓${NC} $header_name: $result"
            return 0
        fi
    fi
}

# Check each header
echo "Checking Frontend Security Headers..."
echo "-----------------------------------"

check_header "strict-transport-security" "max-age=31536000"
check_header "content-security-policy-report-only" ""
check_header "permissions-policy" ""
check_header "x-frame-options" "DENY"
check_header "referrer-policy" "strict-origin-when-cross-origin"
check_header "x-content-type-options" "nosniff"
check_header "x-xss-protection" "1; mode=block"

echo ""
echo "Checking for Deprecated Headers..."
echo "-----------------------------------"

expect_ct=$(curl -sI "https://$DOMAIN" | grep -i "^expect-ct:")
if [ -z "$expect_ct" ]; then
    echo -e "${GREEN}✓${NC} Expect-CT: Correctly absent"
else
    echo -e "${RED}✗${NC} Expect-CT: Still present (should be removed)"
    echo "   Value: $expect_ct"
fi

echo ""
echo "Checking Backend CORS Configuration..."
echo "-----------------------------------"

# Test CORS from allowed origin
cors_allowed=$(curl -sI "https://$BACKEND_DOMAIN/api/v1/health" \
    -H "Origin: https://$DOMAIN" \
    -H "Access-Control-Request-Method: GET" | \
    grep -i "^access-control-allow-origin:")

if [[ "$cors_allowed" == *"$DOMAIN"* ]]; then
    echo -e "${GREEN}✓${NC} CORS allows $DOMAIN"
else
    echo -e "${RED}✗${NC} CORS configuration issue"
    echo "   Result: $cors_allowed"
fi

# Test CORS from disallowed origin
cors_disallowed=$(curl -sI "https://$BACKEND_DOMAIN/api/v1/health" \
    -H "Origin: https://evil.com" \
    -H "Access-Control-Request-Method: GET" | \
    grep -i "^access-control-allow-origin:" || true)

if [ -z "$cors_disallowed" ]; then
    echo -e "${GREEN}✓${NC} CORS correctly blocks unknown origins"
else
    if [[ "$cors_disallowed" == *"*"* ]]; then
        echo -e "${RED}✗${NC} CORS allows wildcard (security risk)"
    else
        echo -e "${YELLOW}⚠${NC} CORS response for unknown origin: $cors_disallowed"
    fi
fi

echo ""
echo "=================================================="
echo "Verification Links:"
echo "=================================================="
echo "• SecurityHeaders.com: https://securityheaders.com/?q=$DOMAIN"
echo "• Mozilla Observatory: https://developer.mozilla.org/en-US/observatory"
echo "• SSL Labs: https://www.ssllabs.com/ssltest/analyze.html?d=$DOMAIN"
echo "• HSTS Preload: https://hstspreload.org/?domain=$DOMAIN"
echo "• CSP Evaluator: https://csp-evaluator.withgoogle.com/"
echo ""

echo "Next Steps:"
echo "1. Visit SecurityHeaders.com link above"
echo "2. Expected Grade: B (Phase 1), A+ (Phase 2)"
echo "3. Monitor CSP violations: vercel logs --follow"
echo "4. Review: SECURITY-VERIFICATION-GUIDE.md"
