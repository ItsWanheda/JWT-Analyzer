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
      org.opencontainers.image.source="https://github.com/ItsWanheda/jwt-analyzer"

# ca-certificates are required for HTTPS JWKS fetching.
# curl is used only to retrieve the build-time wordlist.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        curl && \
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

# Bundle a wordlist in the image so users don't need to download one
# 400 error means SecLists moved the file - update URL if build fails
RUN mkdir -p utils/wordlists && \
    curl -fsSL -o utils/wordlists/common_secrets.txt \
      https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/jwt-secrets.txt && \
    echo "Downloaded $(wc -l < utils/wordlists/common_secrets.txt) secrets" && \
    chown -R jwtuser:jwtuser utils/wordlists

# Switch to non-root - non-negotiable for security tools
USER jwtuser

# Health check helps when running in k8s/swarm
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python main.py --help > /dev/null || exit 1

# exec form = proper signal handling (SIGTERM works for graceful shutdown)
ENTRYPOINT ["python", "main.py"]
CMD ["--help"]