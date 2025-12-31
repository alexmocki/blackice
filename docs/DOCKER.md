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

The workflow uses cache helpers to speed builds and emits basic cache metrics:

- Pip packages are cached across test runs using `actions/cache` keyed on `requirements-dev.txt`. The workflow prints whether the pip cache was a hit and the `pip_install_time` in seconds.
- Docker Buildx uses GitHub Actions cache (`type=gha`) to persist build layers across runs (via `cache-from` / `cache-to`). The workflow measures `docker_build_time` in seconds (build times will improve when cache hits occur).

These timings are printed in workflow logs under the respective job steps ("Show pip cache metrics" and "Show docker build metrics").

Artifacts:
- `pip-metrics`: JSON artifact produced by the `test` job containing `{ "pip_cache_hit": "true|false", "pip_install_time": "<seconds>" }`.
- `docker-metrics`: JSON artifact produced by the `build-and-push` job containing `{ "docker_build_time": "<seconds>" }`.

You can download these artifacts from the GitHub Actions run UI for each workflow run.

## Aggregated metrics report
A scheduled/manual workflow `metrics-collector.yml` aggregates the most recent runs' metrics artifacts and produces `metrics-report.csv` (columns: `run_id, run_number, created_at, html_url, pip_cache_hit, pip_install_time, docker_build_time`).

To collect metrics manually from the Actions UI, trigger the "Metrics collector" workflow or wait for the daily run.

Make sure you have `GITHUB_TOKEN` or appropriate secrets configured to push images to GHCR.
