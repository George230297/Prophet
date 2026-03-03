# Build Stage
FROM python:3.9-slim as builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends gcc && \
    rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Runtime Stage
FROM python:3.9-slim

WORKDIR /app

# Create non-root user
RUN useradd -m -u 1000 prophet
USER 1000

# Copy installed dependencies from builder
COPY --from=builder /root/.local /home/prophet/.local
ENV PATH=/home/prophet/.local/bin:$PATH

# Copy source code
COPY --chown=prophet:prophet src/ ./src/

# Set Environment
ENV PYTHONPATH=/app
ENV APP_ENV=production

# Entrypoint
CMD ["python", "src/main.py"]
