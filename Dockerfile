# Build stage
FROM python:3.13-slim AS builder

WORKDIR /app

# Install build dependencies
RUN pip install --no-cache-dir uv

# Copy project files
COPY pyproject.toml README.md ./
COPY src/ src/

# Install dependencies
RUN uv pip install --system --no-cache .

# Runtime stage
FROM python:3.13-slim

WORKDIR /app

# Install runtime dependencies for clipboard (optional)
RUN apt-get update && apt-get install -y --no-install-recommends \
    xclip \
    && rm -rf /var/lib/apt/lists/*

# Copy installed packages from builder
COPY --from=builder /usr/local/lib/python3.13/site-packages /usr/local/lib/python3.13/site-packages
COPY --from=builder /usr/local/bin/authkeeper /usr/local/bin/authkeeper

# Create non-root user
RUN useradd --create-home --shell /bin/bash authkeeper

# Create data directory
RUN mkdir -p /home/authkeeper/.local/share/authkeeper && \
    chown -R authkeeper:authkeeper /home/authkeeper

USER authkeeper
WORKDIR /home/authkeeper

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV TERM=xterm-256color

# Volume for persistent data
VOLUME ["/home/authkeeper/.local/share/authkeeper"]

# Entry point
ENTRYPOINT ["authkeeper"]
