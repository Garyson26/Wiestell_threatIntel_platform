#!/bin/bash
set -e

echo "Running database migrations..."
alembic upgrade head

echo "Starting SENTINEL API server..."
# --workers 1 is deliberate and load-bearing. uvicorn defaults to one worker, so this
# declares the assumption rather than depending on the default. Four things assume a
# single process per instance: the in-memory rate limiter (otherwise N independent
# budgets), the database pool (2+3 becomes 5N against a shared MySQL account), the
# enrichment semaphore (module-level, so 5N calls in flight), and any in-process cache.
#   5. REDIS_URL is deliberately unset, which is only correct because the fallback is
#      process-local — at N workers a shared store becomes REQUIRED, not optional.
# Raising it means revisiting all five. See tests/test_process_model.py and
# SECURITY_REVIEW.md residual risk #5.
# --no-proxy-headers is deliberate (R-05): uvicorn's proxy_headers defaults to TRUE and its
# middleware rewrites request.client.host from X-Forwarded-For when the peer is in
# FORWARDED_ALLOW_IPS — a second algorithm on the same header as deps.py::_client_ip. This
# app's is kept because it fails closed, is under test and lives in a file. The disable form
# is --no-proxy-headers; `--proxy-headers=false` is invalid and uvicorn refuses to start.
exec uvicorn app.main:app --host 0.0.0.0 --port "${PORT:-8000}" --workers 1 --no-proxy-headers
