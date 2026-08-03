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
# Raising it means revisiting all four. See tests/test_process_model.py and
# SECURITY_REVIEW.md residual risk #5.
exec uvicorn app.main:app --host 0.0.0.0 --port "${PORT:-8000}" --workers 1
