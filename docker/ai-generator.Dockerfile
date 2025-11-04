# Use specific Python version (not latest)
FROM python:3.11.7-slim-bookworm

# Add labels
LABEL maintainer="siem-ai-team"
LABEL service="ai-generator"
LABEL security.scan="enabled"

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Create non-root user
RUN groupadd -r siem && useradd -r -g siem -u 1001 siem && \
    mkdir -p /app /repo/services/event_bridge/queue /repo/playbooks/_library /var/log/siem && \
    chown -R siem:siem /app /repo /var/log/siem

WORKDIR /app

# Copy and install dependencies as root
COPY services/ai_generator/requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY --chown=siem:siem services/ai_generator /app
COPY --chown=siem:siem services/common /repo/services/common
COPY --chown=siem:siem playbooks /repo/playbooks
COPY --chown=siem:siem prompts /repo/prompts

# Switch to non-root user
USER siem

# No health check for background worker, rely on logging

# Use exec form for signals
CMD ["python", "-u", "main.py"]
