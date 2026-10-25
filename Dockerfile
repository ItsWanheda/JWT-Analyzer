# Multi-stage build to keep the final image small.
# Final image is ~150MB instead of ~900MB.

FROM python:3.12-slim AS builder

# Build wheels for all deps in a separate stage
WORKDIR /build
COPY requirements.txt .
RUN pip wheel --no-cache-dir --wheel-dir /wheels -r requirements.txt


FROM python:3.12-slim

# Image metadata - shows up in `docker inspect`
LABEL org.opencontainers.image.title="jwt-analyzer" \
      org.opencontainers.image.description="JWT security analysis CLI" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="2.0.0.dev0" \
      org.opencontainers.image.source="https://github.com/ItsWanheda/jwt-analyzer"

# ca-certificates are required for HTTPS JWKS fetching.
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Create non-root user before we copy anything
# Using uid 1000 because that matches most host users
RUN groupadd -r jwtuser -g 1000 && \
    useradd -r -u 1000 -g jwtuser -m -d /home/jwtuser -s /bin/bash jwtuser

WORKDIR /app

# Install Python deps from prebuilt wheels (way faster than pip install at runtime)
COPY --from=builder /wheels /wheels
COPY requirements.txt .
RUN pip install --no-cache-dir --no-index --find-links=/wheels -r requirements.txt && \
    rm -rf /wheels

# Now copy the actual app
COPY --chown=jwtuser:jwtuser . .

# The repository's checked-in starter wordlist is copied with the source.
# Larger wordlists should be supplied explicitly by the operator.

# Switch to non-root - non-negotiable for security tools
USER jwtuser

# Health check helps when running in k8s/swarm
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python main.py --help > /dev/null || exit 1

# exec form = proper signal handling (SIGTERM works for graceful shutdown)
ENTRYPOINT ["python", "main.py"]
CMD ["--help"]