FROM python:3.12-slim

WORKDIR /app

# Copy only what's needed to run the gateway
COPY python/qvault_threshold.py      ./python/qvault_threshold.py
COPY examples/gateway/qvault_gateway.py ./qvault_gateway.py

# The only external dependency
RUN pip install --no-cache-dir cryptography

# gateway.json is mounted at runtime (see docker-compose.yml)
# Default port — can be overridden in gateway.json
EXPOSE 8080

# Bind to all interfaces inside the container
ENTRYPOINT ["python", "qvault_gateway.py", "serve", "/config/gateway.json", "--host", "0.0.0.0"]
