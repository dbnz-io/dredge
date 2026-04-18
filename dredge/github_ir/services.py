from __future__ import annotations

from typing import Any, Dict, Optional
import requests

from .config import GitHubIRConfig


class GitHubServiceRegistry:
    """
    Wraps a requests.Session configured for the GitHub API.
    """

    def __init__(self, config: GitHubIRConfig) -> None:
        self._config = config
        token = config.resolve_token()

        self._session = requests.Session()
        self._session.headers.update({
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
        })
        self._base_url = config.base_url.rstrip("/")

    @property
    def audit_log_path_base(self) -> str:
        org = getattr(self._config, "org", None)
        enterprise = getattr(self._config, "enterprise", None)

        if org:
            return f"/orgs/{org}/audit-log"
        if enterprise:
            return f"/enterprises/{enterprise}/audit-log"
        raise RuntimeError("GitHubIRConfig must define either 'org' or 'enterprise'")

    def get(self, path: str, params: Optional[Dict[str, Any]] = None) -> requests.Response:
        url = f"{self._base_url}{path}"
        return self._session.get(url, params=params)

    def post(self, path: str, json: Optional[Dict[str, Any]] = None) -> requests.Response:
        return self._session.post(f"{self._base_url}{path}", json=json)

    def put(self, path: str, json: Optional[Dict[str, Any]] = None) -> requests.Response:
        return self._session.put(f"{self._base_url}{path}", json=json)

    def delete(self, path: str) -> requests.Response:
        return self._session.delete(f"{self._base_url}{path}")

    def patch(self, path: str, json: Optional[Dict[str, Any]] = None) -> requests.Response:
        return self._session.patch(f"{self._base_url}{path}", json=json)
