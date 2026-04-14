#!/bin/bash
# Render.com build script for backend

set -e  # Exit on error

echo "📦 Installing Python dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

echo "🌍 Downloading GeoLite2 database..."
python download_geolite2.py || echo "⚠️  GeoLite2 download failed - continuing anyway"

echo "🗄️  Running database migrations..."
alembic upgrade head

echo "✅ Build complete!"
