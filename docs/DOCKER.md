# Docker and Local Development

This project includes simple Docker and docker-compose configurations to run the API locally or in CI.

## Dockerfile
- Built from python:3.11-slim
- Installs dependencies from `requirements-dev.txt` and runs the API via `uvicorn blackice.api.app:app` on port `8080`.

Build an image locally:

  docker build -t blackice:local .

Run it:

  docker run -p 8080:8080 blackice:local

## docker-compose
Use `docker-compose up` to run the service with code mounted into the container (useful for local development).
The `app` service exposes port 8080 and runs uvicorn with `--reload`.

## CI image
A GitHub Actions workflow `docker-build.yml` builds and pushes multi-arch images to GitHub Container Registry (`ghcr.io/<owner>/blackice`) when changes are pushed to `main`.

Make sure you have `GITHUB_TOKEN` or appropriate secrets configured to push images to GHCR.
