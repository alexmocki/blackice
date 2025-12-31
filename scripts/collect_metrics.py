#!/usr/bin/env python3
"""Collect pip/docker metrics artifacts from recent workflow runs and aggregate to CSV.

Usage: python scripts/collect_metrics.py --limit 20 --output artifacts/metrics-report.csv

Environment:
- GITHUB_TOKEN (required)
- GITHUB_REPOSITORY (owner/repo) (optional, fallback to git remote)
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import os
import sys
import zipfile
from typing import Any, Dict, List, Optional

import httpx

API = "https://api.github.com"


def repo_from_env() -> Optional[str]:
    repo = os.getenv("GITHUB_REPOSITORY")
    if repo:
        return repo
    # try git remote
    try:
        from subprocess import check_output

        out = check_output(["git", "config", "--get", "remote.origin.url"]).decode().strip()
        # formats: git@github.com:owner/repo.git or https://github.com/owner/repo.git
        if out.startswith("git@"):
            part = out.split(":", 1)[1]
        else:
            part = out.split("github.com/", 1)[1]
        if part.endswith(".git"):
            part = part[:-4]
        return part
    except Exception:
        return None


def list_workflow_runs(repo: str, workflow_file: str, limit: int, token: str) -> List[Dict[str, Any]]:
    url = f"{API}/repos/{repo}/actions/workflows/{workflow_file}/runs?per_page={limit}"
    headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github+json"}
    r = httpx.get(url, headers=headers, timeout=30.0)
    r.raise_for_status()
    j = r.json()
    return j.get("workflow_runs", [])


def list_run_artifacts(repo: str, run_id: int, token: str) -> List[Dict[str, Any]]:
    url = f"{API}/repos/{repo}/actions/runs/{run_id}/artifacts"
    headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github+json"}
    r = httpx.get(url, headers=headers, timeout=30.0)
    r.raise_for_status()
    return r.json().get("artifacts", [])


def download_artifact(archive_url: str, token: str) -> bytes:
    # archive_url is typically the `archive_download_url` that returns a zip
    headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github+json"}
    r = httpx.get(archive_url, headers=headers, timeout=60.0)
    r.raise_for_status()
    return r.content


def extract_metrics_from_zip(content: bytes) -> Dict[str, Any]:
    with zipfile.ZipFile(io.BytesIO(content)) as z:
        for name in z.namelist():
            if name.endswith('.json'):
                with z.open(name) as fh:
                    try:
                        return json.load(fh)
                    except Exception:
                        continue
    return {}


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--workflow-file", default="docker-build.yml", help="workflow file name to inspect")
    p.add_argument("--limit", type=int, default=20, help="how many recent runs to examine")
    p.add_argument("--output", default="artifacts/metrics-report.csv")
    args = p.parse_args(argv)

    token = os.getenv("GITHUB_TOKEN")
    if not token:
        print("GITHUB_TOKEN not set", file=sys.stderr)
        return 2

    repo = repo_from_env()
    if not repo:
        print("Could not determine repo (set GITHUB_REPOSITORY or run inside a git repo)", file=sys.stderr)
        return 2

    runs = list_workflow_runs(repo, args.workflow_file, args.limit, token)

    rows = []
    for r in runs:
        run_id = r.get("id")
        number = r.get("run_number")
        created_at = r.get("created_at")
        html_url = r.get("html_url")

        artifacts = list_run_artifacts(repo, run_id, token)
        pip = {}
        docker = {}
        for a in artifacts:
            name = a.get("name")
            archive = a.get("archive_download_url")
            if name in ("pip-metrics", "docker-metrics") and archive:
                try:
                    content = download_artifact(archive, token)
                    data = extract_metrics_from_zip(content)
                    if name == "pip-metrics":
                        pip = data
                    elif name == "docker-metrics":
                        docker = data
                except Exception as exc:
                    print(f"Failed to download/parse artifact {name} for run {run_id}: {exc}")

        rows.append({
            "run_id": run_id,
            "run_number": number,
            "created_at": created_at,
            "html_url": html_url,
            "pip_cache_hit": pip.get("pip_cache_hit"),
            "pip_install_time": pip.get("pip_install_time"),
            "docker_build_time": docker.get("docker_build_time"),
        })

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=["run_id", "run_number", "created_at", "html_url", "pip_cache_hit", "pip_install_time", "docker_build_time"]) 
        writer.writeheader()
        for r in rows:
            writer.writerow(r)

    print(f"Wrote {len(rows)} rows to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
