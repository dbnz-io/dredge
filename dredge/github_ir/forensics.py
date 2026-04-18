from __future__ import annotations

from typing import Any, Dict, List, Optional

import requests
import requests.exceptions

from .config import GitHubIRConfig
from .services import GitHubServiceRegistry
from .models import OperationResult
from ..log import get_logger, event as log_event

_log = get_logger(__name__)


class GitHubIRForensics:
    """
    Evidence collection and configuration snapshot methods for GitHub IR.

    Example:
        dredge.github_ir.forensics.get_org_settings()
        dredge.github_ir.forensics.get_branch_protection("repo", "main")
    """

    def __init__(self, services: GitHubServiceRegistry, config: GitHubIRConfig) -> None:
        self._services = services
        self._config = config

    @property
    def _org(self) -> str:
        if not self._config.org:
            raise RuntimeError(
                "GitHubIRForensics requires org-scoped GitHubIRConfig"
            )
        return self._config.org

    def _paginate(
        self,
        path: str,
        *,
        max_items: int,
        params: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """Simple paginator without backoff (raises RuntimeError on HTTP errors)."""
        items: List[Dict[str, Any]] = []
        page = 1
        per_page = 100
        base = {**(params or {}), "per_page": per_page}

        while len(items) < max_items:
            resp = self._services.get(path, params={**base, "page": page})
            if resp.status_code != 200:
                raise RuntimeError(f"GitHub API error {resp.status_code}: {resp.text[:200]}")
            page_data = resp.json()
            if not isinstance(page_data, list) or not page_data:
                break
            items.extend(page_data[:max_items - len(items)])
            if len(page_data) < per_page:
                break
            page += 1

        return items

    # --------------------
    # Org
    # --------------------

    def get_org_settings(self) -> OperationResult:
        """
        Capture a full configuration snapshot of the organization.

        Returns the org object including billing info, feature flags,
        security settings (e.g. two_factor_requirement_enabled), and member counts.
        """
        result = OperationResult(
            operation="get_org_settings",
            target=f"org={self._org}",
            success=True,
        )
        try:
            resp = self._services.get(f"/orgs/{self._org}")
            if resp.status_code == 200:
                result.details["org"] = resp.json()
                _log.info(log_event("github_ir_forensics", "get_org_settings.success", target=result.target))
            else:
                result.add_error(f"GitHub API error {resp.status_code}: {resp.text[:200]}")
                _log.warning(log_event("github_ir_forensics", "get_org_settings.error", target=result.target, status=resp.status_code))
        except requests.exceptions.RequestException as exc:
            result.add_error(str(exc))
            _log.error(log_event("github_ir_forensics", "get_org_settings.error", target=result.target, error=str(exc)))
        return result

    # --------------------
    # Repositories
    # --------------------

    def get_repo_metadata(self, repo: str) -> OperationResult:
        """
        Capture the full configuration snapshot of a repository.

        Includes visibility, default branch, archived/disabled status,
        security settings, and feature flags.
        """
        result = OperationResult(
            operation="get_repo_metadata",
            target=f"org={self._org},repo={repo}",
            success=True,
        )
        try:
            resp = self._services.get(f"/repos/{self._org}/{repo}")
            if resp.status_code == 200:
                result.details["repo"] = resp.json()
                _log.info(log_event("github_ir_forensics", "get_repo_metadata.success", target=result.target))
            else:
                result.add_error(f"GitHub API error {resp.status_code}: {resp.text[:200]}")
                _log.warning(log_event("github_ir_forensics", "get_repo_metadata.error", target=result.target, status=resp.status_code))
        except requests.exceptions.RequestException as exc:
            result.add_error(str(exc))
            _log.error(log_event("github_ir_forensics", "get_repo_metadata.error", target=result.target, error=str(exc)))
        return result

    def list_repo_collaborators(
        self,
        repo: str,
        *,
        max_items: int = 200,
    ) -> OperationResult:
        """
        List all collaborators on a repository (members + outside collaborators).

        Each entry includes login, id, and permissions (push/pull/admin/maintain/triage).
        """
        result = OperationResult(
            operation="list_repo_collaborators",
            target=f"org={self._org},repo={repo}",
            success=True,
        )
        try:
            collaborators = self._paginate(
                f"/repos/{self._org}/{repo}/collaborators",
                max_items=max_items,
            )
            result.details["collaborators"] = collaborators
            result.details["statistics"] = {"total": len(collaborators), "repo": repo}
            _log.info(log_event("github_ir_forensics", "list_repo_collaborators.success", target=result.target, total=len(collaborators)))
        except (RuntimeError, requests.exceptions.RequestException) as exc:
            result.add_error(str(exc))
            _log.error(log_event("github_ir_forensics", "list_repo_collaborators.error", target=result.target, error=str(exc)))
        return result

    def get_branch_protection(self, repo: str, branch: str) -> OperationResult:
        """
        Get branch protection rules for a repository branch.

        Returns the full protection configuration: required reviews, status checks,
        restrictions, etc. If no protection is configured (404), success=True with
        details["protected"] = False — this is diagnostic information, not an error.

        Args:
            repo:   Repository name (without org prefix).
            branch: Branch name (e.g. "main").
        """
        result = OperationResult(
            operation="get_branch_protection",
            target=f"org={self._org},repo={repo},branch={branch}",
            success=True,
        )
        try:
            resp = self._services.get(
                f"/repos/{self._org}/{repo}/branches/{branch}/protection"
            )
            if resp.status_code == 200:
                result.details["protected"] = True
                result.details["protection"] = resp.json()
                _log.info(log_event("github_ir_forensics", "get_branch_protection.success", target=result.target))
            elif resp.status_code == 404:
                # Branch exists but has no protection rules — not an error
                result.details["protected"] = False
                result.details["protection"] = None
                _log.info(log_event("github_ir_forensics", "get_branch_protection.unprotected", target=result.target))
            else:
                result.add_error(f"GitHub API error {resp.status_code}: {resp.text[:200]}")
                _log.warning(log_event("github_ir_forensics", "get_branch_protection.error", target=result.target, status=resp.status_code))
        except requests.exceptions.RequestException as exc:
            result.add_error(str(exc))
            _log.error(log_event("github_ir_forensics", "get_branch_protection.error", target=result.target, error=str(exc)))
        return result

    # --------------------
    # Webhooks
    # --------------------

    def list_org_webhooks(self) -> OperationResult:
        """
        List all organization-level webhooks.

        Webhook objects include id, name, active flag, event subscriptions,
        and config.url. Use this to inventory potentially malicious hooks
        created for persistence or data exfiltration.
        """
        result = OperationResult(
            operation="list_org_webhooks",
            target=f"org={self._org}",
            success=True,
        )
        try:
            webhooks = self._paginate(f"/orgs/{self._org}/hooks", max_items=200)
            result.details["webhooks"] = webhooks
            result.details["statistics"] = {"total": len(webhooks)}
            _log.info(log_event("github_ir_forensics", "list_org_webhooks.success", target=result.target, total=len(webhooks)))
        except (RuntimeError, requests.exceptions.RequestException) as exc:
            result.add_error(str(exc))
            _log.error(log_event("github_ir_forensics", "list_org_webhooks.error", target=result.target, error=str(exc)))
        return result

    def list_repo_webhooks(self, repo: str) -> OperationResult:
        """
        List all repository-level webhooks.

        Args:
            repo: Repository name (without org prefix).
        """
        result = OperationResult(
            operation="list_repo_webhooks",
            target=f"org={self._org},repo={repo}",
            success=True,
        )
        try:
            webhooks = self._paginate(f"/repos/{self._org}/{repo}/hooks", max_items=200)
            result.details["webhooks"] = webhooks
            result.details["statistics"] = {"total": len(webhooks), "repo": repo}
            _log.info(log_event("github_ir_forensics", "list_repo_webhooks.success", target=result.target, total=len(webhooks)))
        except (RuntimeError, requests.exceptions.RequestException) as exc:
            result.add_error(str(exc))
            _log.error(log_event("github_ir_forensics", "list_repo_webhooks.error", target=result.target, error=str(exc)))
        return result

    # --------------------
    # Commit history
    # --------------------

    def get_commit_history(
        self,
        repo: str,
        branch: str,
        *,
        max_commits: int = 100,
    ) -> OperationResult:
        """
        Capture the commit history for a repository branch.

        Useful for reconstructing what changed on a branch during the incident
        window. Each entry includes SHA, author, committer, message, and timestamp.

        Args:
            repo:        Repository name (without org prefix).
            branch:      Branch name or commit SHA.
            max_commits: Maximum commits to retrieve.
        """
        result = OperationResult(
            operation="get_commit_history",
            target=f"org={self._org},repo={repo},branch={branch}",
            success=True,
        )
        try:
            commits = self._paginate(
                f"/repos/{self._org}/{repo}/commits",
                params={"sha": branch},
                max_items=max_commits,
            )
            result.details["commits"] = commits
            result.details["statistics"] = {"total": len(commits), "branch": branch}
            _log.info(log_event("github_ir_forensics", "get_commit_history.success", target=result.target, total=len(commits)))
        except (RuntimeError, requests.exceptions.RequestException) as exc:
            result.add_error(str(exc))
            _log.error(log_event("github_ir_forensics", "get_commit_history.error", target=result.target, error=str(exc)))
        return result

    # --------------------
    # File at commit
    # --------------------

    def get_file_at_commit(
        self,
        repo: str,
        path: str,
        ref: str,
    ) -> OperationResult:
        """
        Retrieve the contents of a file at a specific commit or branch.

        Use this to capture the exact state of a workflow file, config, or
        script at a suspicious commit before it is overwritten.

        Args:
            repo: Repository name (without org prefix).
            path: File path within the repository (e.g. ".github/workflows/ci.yml").
            ref:  Commit SHA, branch name, or tag.
        """
        result = OperationResult(
            operation="get_file_at_commit",
            target=f"org={self._org},repo={repo},path={path},ref={ref}",
            success=True,
        )
        try:
            resp = self._services.get(
                f"/repos/{self._org}/{repo}/contents/{path}",
                params={"ref": ref},
            )
            if resp.status_code == 200:
                data = resp.json()
                result.details["file"] = data
                # Decode content if base64-encoded
                content_b64 = data.get("content", "")
                if content_b64 and data.get("encoding") == "base64":
                    import base64
                    try:
                        result.details["content_decoded"] = base64.b64decode(
                            content_b64.replace("\n", "")
                        ).decode("utf-8", errors="replace")
                    except Exception:
                        result.details["content_decoded"] = None
                _log.info(log_event("github_ir_forensics", "get_file_at_commit.success", target=result.target))
            elif resp.status_code == 404:
                result.add_error(f"File not found: {path} at ref {ref}")
            else:
                result.add_error(f"GitHub API error {resp.status_code}: {resp.text[:200]}")
                _log.warning(log_event("github_ir_forensics", "get_file_at_commit.error", target=result.target, status=resp.status_code))
        except requests.exceptions.RequestException as exc:
            result.add_error(str(exc))
            _log.error(log_event("github_ir_forensics", "get_file_at_commit.error", target=result.target, error=str(exc)))
        return result

    # --------------------
    # Actions workflows
    # --------------------

    def list_repo_actions_workflows(self, repo: str) -> OperationResult:
        """
        List all GitHub Actions workflow definitions in a repository.

        Returns workflow names, file paths, state (active/disabled), and IDs.
        Use IDs with disable_actions_workflow to stop a suspicious workflow.
        """
        result = OperationResult(
            operation="list_repo_actions_workflows",
            target=f"org={self._org},repo={repo}",
            success=True,
        )
        try:
            resp = self._services.get(f"/repos/{self._org}/{repo}/actions/workflows")
            if resp.status_code == 200:
                data = resp.json()
                workflows = data.get("workflows", [])
                result.details["workflows"] = workflows
                result.details["statistics"] = {"total": len(workflows), "repo": repo}
                _log.info(log_event("github_ir_forensics", "list_repo_actions_workflows.success", target=result.target, total=len(workflows)))
            else:
                result.add_error(f"GitHub API error {resp.status_code}: {resp.text[:200]}")
                _log.warning(log_event("github_ir_forensics", "list_repo_actions_workflows.error", target=result.target, status=resp.status_code))
        except requests.exceptions.RequestException as exc:
            result.add_error(str(exc))
            _log.error(log_event("github_ir_forensics", "list_repo_actions_workflows.error", target=result.target, error=str(exc)))
        return result

    # --------------------
    # Team repos
    # --------------------

    def get_team_repos(
        self,
        team_slug: str,
        *,
        max_repos: int = 200,
    ) -> OperationResult:
        """
        List repositories accessible to an organization team.

        Use this for blast-radius assessment: which repos can members of a
        potentially compromised team read or write?

        Args:
            team_slug:  Team slug (from list_org_teams).
            max_repos:  Maximum repos to return.
        """
        result = OperationResult(
            operation="get_team_repos",
            target=f"org={self._org},team={team_slug}",
            success=True,
        )
        try:
            repos = self._paginate(
                f"/orgs/{self._org}/teams/{team_slug}/repos",
                max_items=max_repos,
            )
            result.details["repos"] = repos
            result.details["statistics"] = {"total": len(repos), "team": team_slug}
            _log.info(log_event("github_ir_forensics", "get_team_repos.success", target=result.target, total=len(repos)))
        except (RuntimeError, requests.exceptions.RequestException) as exc:
            result.add_error(str(exc))
            _log.error(log_event("github_ir_forensics", "get_team_repos.error", target=result.target, error=str(exc)))
        return result
