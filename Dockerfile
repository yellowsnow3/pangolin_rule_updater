FROM python:3.12-slim

# Install runtime libs
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# Copy application code
WORKDIR /app
COPY update_ip.py /app/update_ip.py

# config.yml is expected to be mounted at /app/config.yml via a volume.
# Override the path with the CONFIG_FILE environment variable if needed.
ENV CONFIG_FILE=/app/config.yml

# Entrypoint
CMD ["python", "-u", "/app/update_ip.py"]

