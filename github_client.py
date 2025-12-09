"""
Lightweight GitHub client used for repository discovery and manifest retrieval.

The client is intentionally minimal and keeps the surface area small so it can be
swapped out for another HTTP layer or caching strategy.
"""

from __future__ import annotations

import base64
import datetime as dt
import os
from typing import Dict, Iterable, List, Optional

import requests

GITHUB_API = "https://api.github.com"


class GitHubClient:
    def __init__(self, token: Optional[str] = None, session: Optional[requests.Session] = None):
        self.session = session or requests.Session()
        self.token = token or os.getenv("GITHUB_TOKEN")
        if self.token:
            self.session.headers.update({"Authorization": f"token {self.token}"})
        self.session.headers.update({"Accept": "application/vnd.github+json"})
        self.cache: Dict[str, Dict[str, str]] = {"files": {}, "repos": {}}

    def _request(self, url: str, params: Optional[Dict] = None) -> requests.Response:
        resp = self.session.get(url, params=params or {})
        # Minimal backoff on rate limits
        if resp.status_code == 403 and resp.headers.get("X-RateLimit-Remaining") == "0":
            reset = resp.headers.get("X-RateLimit-Reset")
            raise RuntimeError(f"GitHub rate limit exceeded. Resets at {reset}.")
        resp.raise_for_status()
        return resp

    def fetch_repos(
        self,
        owner: str,
        include_forks: bool = True,
        min_updated: Optional[dt.datetime] = None,
    ) -> List[Dict]:
        """Fetch public repositories for a user/org with optional filters."""
        repos: List[Dict] = []
        page = 1
        while True:
            url = f"{GITHUB_API}/users/{owner}/repos"
            resp = self._request(url, params={"per_page": 100, "page": page, "type": "public", "sort": "updated"})
            batch = resp.json()
            if not batch:
                break
            for repo in batch:
                if not include_forks and repo.get("fork"):
                    continue
                if min_updated:
                    pushed_at = dt.datetime.fromisoformat(repo["pushed_at"].replace("Z", "+00:00"))
                    if pushed_at < min_updated:
                        continue
                repos.append(repo)
            page += 1
        return repos

    def list_repository_files(self, owner: str, repo: str, directories: Iterable[str]) -> List[Dict]:
        """List files in selected directories (root + common config dirs)."""
        files: List[Dict] = []
        for path in directories:
            cache_key = f"{owner}/{repo}/{path}"
            if cache_key in self.cache["files"]:
                files.extend(self.cache["files"][cache_key])
                continue
            url = f"{GITHUB_API}/repos/{owner}/{repo}/contents/{path}".rstrip("/")
            try:
                resp = self._request(url)
            except requests.HTTPError as exc:
                if exc.response.status_code == 404:
                    continue
                raise
            data = resp.json()
            if isinstance(data, list):
                files.extend(data)
                self.cache["files"][cache_key] = data
        return files

    def fetch_file_text(self, owner: str, repo: str, path: str) -> Optional[str]:
        """Download a file's text content."""
        cache_key = f"{owner}/{repo}/{path}"
        if cache_key in self.cache["repos"]:
            return self.cache["repos"][cache_key]
        url = f"{GITHUB_API}/repos/{owner}/{repo}/contents/{path}"
        try:
            resp = self._request(url)
        except requests.HTTPError as exc:
            if exc.response.status_code == 404:
                return None
            raise
        payload = resp.json()
        content = payload.get("content")
        if not content:
            return None
        decoded = base64.b64decode(content).decode("utf-8", errors="ignore")
        self.cache["repos"][cache_key] = decoded
        return decoded
