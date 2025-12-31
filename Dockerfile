# Lightweight Dockerfile for running BlackIce API
FROM python:3.11-slim

# Set workdir
WORKDIR /app

# install minimal deps
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential git \
    && rm -rf /var/lib/apt/lists/*

# Copy only dependency files first for caching
COPY pyproject.toml requirements-dev.txt ./

# Install runtime and test deps (use requirements-dev for now to include test deps)
RUN pip install --no-cache-dir -r requirements-dev.txt

# Copy project
COPY . /app

# Expose port for API
EXPOSE 8080

# Default command (production): run uvicorn on port 8080
CMD ["uvicorn", "blackice.api.app:app", "--host", "0.0.0.0", "--port", "8080"]
