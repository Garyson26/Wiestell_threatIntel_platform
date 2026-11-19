#!/bin/bash
# Render.com build script for backend

set -e  # Exit on error

echo "📦 Installing Python dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

echo "🗄️  Running database migrations..."
alembic upgrade head

echo "✅ Build complete!"
