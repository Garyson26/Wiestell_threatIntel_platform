FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create data directory for GeoIP DB
RUN mkdir -p /app/data

EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD curl -f http://localhost:${PORT:-8000}/api/v1/health || exit 1

# Strip CRLF before making it executable. .gitattributes forces LF in the working
# tree, but this also covers a file that arrived some other way — a zip download,
# an editor that rewrote it, a bind mount from a Windows host. Without it the
# shebang becomes `#!/bin/bash` and the container exits 255 with
# "exec ./start.sh: no such file or directory", which names the script rather than
# the missing interpreter and is correspondingly hard to read.
RUN sed -i 's/$//' start.sh && chmod +x start.sh

CMD ["./start.sh"]
