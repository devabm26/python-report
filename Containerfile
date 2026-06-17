# =============================================================================
# Containerfile — Thoughts Dashboard
# =============================================================================
# Base image: Red Hat UBI 9 Python 3.11
#   - Enterprise-grade, RHEL security patches (specs/deployment/dockerfile.spec)
#   - Runs as non-root UID 1001 by default
#   - Free to use; optimised for OpenShift/Kubernetes
#
# Build:
#   podman build -t thoughts-dashboard:latest .
#
# Run (inject secrets at runtime — never bake them in):
#   podman run --rm -p 8000:8000 \
#     -e DB_HOST=... -e DB_NAME=... -e DB_USER=... \
#     -e DB_PASSWORD=... -e SECRET_KEY=... \
#     thoughts-dashboard:latest
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1: builder
# Install build tools + compile Python packages into an isolated venv.
# Nothing from this stage reaches the final image except /opt/venv.
# -----------------------------------------------------------------------------
FROM registry.access.redhat.com/ubi9/python-311:latest AS builder

# Root needed to install OS build packages (REQ-4: remove in final stage)
USER 0

RUN dnf install -y \
        gcc \
        postgresql-devel \
    && dnf clean all \
    && rm -rf /var/cache/dnf

# Isolated virtual environment keeps the final image clean
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy dependency manifest first — maximises layer cache reuse
COPY requirements.txt .

RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir -r requirements.txt

# -----------------------------------------------------------------------------
# Stage 2: runtime
# Minimal image: only runtime OS libs + pre-built venv + application code.
# NO build tools, NO dev dependencies, NO secrets.
# -----------------------------------------------------------------------------
FROM registry.access.redhat.com/ubi9/python-311:latest

LABEL org.opencontainers.image.title="Thoughts Dashboard" \
      org.opencontainers.image.description="PostgreSQL reporting dashboard for the Thoughts application" \
      org.opencontainers.image.base.name="registry.access.redhat.com/ubi9/python-311"

# Root needed to install OS runtime packages
USER 0

# libpq is the only runtime dependency needed by psycopg2 (REQ-4)
RUN dnf install -y \
        postgresql \
    && dnf clean all \
    && rm -rf /var/cache/dnf

# Bring in the pre-built venv from the builder stage (REQ-1: multi-stage)
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Python runtime tuning — no sensitive values here (REQ-3: no secrets in ENV)
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# Copy application source with correct ownership (REQ-2: run as UID 1001)
COPY --chown=1001:0 src/       /app/src/
COPY --chown=1001:0 config/    /app/config/

# Red Hat UBI Python images already run as UID 1001 — set explicitly for
# clarity and to satisfy container security scanners (REQ-2)
USER 1001

# Document the port (REQ-6)
EXPOSE 8000

# Health check used by OpenShift liveness/readiness probes (REQ-5)
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c \
        "import urllib.request, sys; \
         r = urllib.request.urlopen('http://localhost:8000/health', timeout=4); \
         sys.exit(0 if r.status == 200 else 1)"

# Production WSGI server — never use flask run in a container (REQ-7)
# Workers: 2 * CPU + 1 is the Gunicorn recommendation; 4 is a safe default.
CMD ["gunicorn", \
     "--bind", "0.0.0.0:8000", \
     "--workers", "4", \
     "--timeout", "60", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "src.app:app"]
