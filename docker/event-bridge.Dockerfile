# Use specific Python version (not latest)
FROM python:3.11.7-slim-bookworm

# Add labels for identification
LABEL maintainer="siem-ai-team"
LABEL service="event-bridge"
LABEL security.scan="enabled"

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Create non-root user
RUN groupadd -r siem && useradd -r -g siem -u 1000 siem && \
    mkdir -p /app /repo/services/event_bridge/queue /var/log/siem && \
    chown -R siem:siem /app /repo /var/log/siem

WORKDIR /app

# Copy and install dependencies as root
COPY services/event_bridge/requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir gunicorn==21.2.0

# Copy application code
COPY --chown=siem:siem services/event_bridge /app
COPY --chown=siem:siem services/common /repo/services/common
COPY --chown=siem:siem schemas /repo/schemas

# Switch to non-root user
USER siem

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:5000/health', timeout=5)" || exit 1

# Expose port
EXPOSE 5000

# Use gunicorn for production
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--timeout", "30", "--access-logfile", "-", "--error-logfile", "-", "app:app"]
