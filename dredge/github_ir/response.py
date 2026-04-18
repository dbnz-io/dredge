from __future__ import annotations

from typing import Optional

import requests
import requests.exceptions

from .config import GitHubIRConfig
from .services import GitHubServiceRegistry
from .models import OperationResult
from ..log import get_logger, event as log_event

_log = get_logger(__name__)

_SUCCESS_CODES = frozenset({200, 204})


class GitHubIRResponse:
    """
    Containment / response actions against a GitHub organization.

    Example:
        dredge.github_ir.response.block_org_member("evil-actor")
        dredge.github_ir.response.archive_repository("compromised-repo")
    """

    def __init__(self, services: GitHubServiceRegistry, config: GitHubIRConfig) -> None:
        self._services = services
        self._config = config

    @property
    def _org(self) -> str:
        """Return org slug or raise if not configured (enterprise-only config)."""
        if not self._config.org:
            raise RuntimeError(
                "GitHubIRResponse requires org-scoped GitHubIRConfig "
                "(enterprise configs are not supported for response actions)"
            )
        return self._config.org

    @staticmethod
    def _error_body(resp: requests.Response) -> str:
        try:
            return str(resp.json())
        except ValueError:
            return resp.text[:200]

    # --------------------
    # Member management
    # --------------------

    def block_org_member(self, username: str) -> OperationResult:
        """
        Block a user from interacting with the organization.

        The user loses access to all org repositories and cannot open issues,
        comment, or fork. Unlike removing membership, this also prevents
        future interaction from non-members.
        """
        result = OperationResult(
            operation="block_org_member",
            target=f"org={self._org},user={username}",
            success=True,
        )
        try:
            resp = self._services.put(f"/orgs/{self._org}/blocks/{username}")
            if resp.status_code in _SUCCESS_CODES:
                result.details["blocked"] = True
                _log.info(log_event("github_ir_response", "block_org_member.success", target=result.target))
            else:
                result.add_error(f"GitHub API error {resp.status_code}: {self._error_body(resp)}")
                _log.warning(log_event("github_ir_response", "block_org_member.error", target=result.target, status=resp.status_code))
        except requests.exceptions.RequestException as exc:
            result.add_error(str(exc))
            _log.error(log_event("github_ir_response", "block_org_member.error", target=result.target, error=str(exc)))
        return result

    def remove_org_member(self, username: str) -> OperationResult:
        """
        Remove a user from the organization.

        The user loses access to all private org repositories. If the user
        has admin access to any repos, their access is revoked.
        """
        result = OperationResult(
            operation="remove_org_member",
            target=f"org={self._org},user={username}",
            success=True,
        )
        try:
            resp = self._services.delete(f"/orgs/{self._org}/members/{username}")
            if resp.status_code in _SUCCESS_CODES:
                result.details["removed"] = True
                _log.info(log_event("github_ir_response", "remove_org_member.success", target=result.target))
            else:
                result.add_error(f"GitHub API error {resp.status_code}: {self._error_body(resp)}")
                _log.warning(log_event("github_ir_response", "remove_org_member.error", target=result.target, status=resp.status_code))
        except requests.exceptions.RequestException as exc:
            result.add_error(str(exc))
            _log.error(log_event("github_ir_response", "remove_org_member.error", target=result.target, error=str(exc)))
        return result

    def remove_repo_collaborator(self, repo: str, username: str) -> OperationResult:
        """
        Remove a collaborator's direct access to a specific repository.

        NOTE: GitHub returns 422 if the user is an org member (not a direct
        collaborator). Use remove_org_member for org members instead.
        """
        result = OperationResult(
            operation="remove_repo_collaborator",
            target=f"org={self._org},repo={repo},user={username}",
            success=True,
        )
        try:
            resp = self._services.delete(f"/repos/{self._org}/{repo}/collaborators/{username}")
            if resp.status_code in _SUCCESS_CODES:
                result.details["removed"] = True
                _log.info(log_event("github_ir_response", "remove_repo_collaborator.success", target=result.target))
            else:
                result.add_error(f"GitHub API error {resp.status_code}: {self._error_body(resp)}")
                _log.warning(log_event("github_ir_response", "remove_repo_collaborator.error", target=result.target, status=resp.status_code))
        except requests.exceptions.RequestException as exc:
            result.add_error(str(exc))
            _log.error(log_event("github_ir_response", "remove_repo_collaborator.error", target=result.target, error=str(exc)))
        return result

    # --------------------
    # Deploy keys
    # --------------------

    def revoke_deploy_key(self, repo: str, key_id: int) -> OperationResult:
        """
        Delete a deploy key from a repository.

        Deploy keys grant read (or write) access to a single repository.
        Revoking them immediately cuts access for any automation using that key.
        """
        result = OperationResult(
            operation="revoke_deploy_key",
            target=f"org={self._org},repo={repo},key_id={key_id}",
            success=True,
        )
        try:
            resp = self._services.delete(f"/repos/{self._org}/{repo}/keys/{key_id}")
            if resp.status_code in _SUCCESS_CODES:
                result.details["revoked"] = True
                _log.info(log_event("github_ir_response", "revoke_deploy_key.success", target=result.target))
            else:
                result.add_error(f"GitHub API error {resp.status_code}: {self._error_body(resp)}")
                _log.warning(log_event("github_ir_response", "revoke_deploy_key.error", target=result.target, status=resp.status_code))
        except requests.exceptions.RequestException as exc:
            result.add_error(str(exc))
            _log.error(log_event("github_ir_response", "revoke_deploy_key.error", target=result.target, error=str(exc)))
        return result

    # --------------------
    # Webhooks
    # --------------------

    def delete_org_webhook(self, hook_id: int) -> OperationResult:
        """
        Delete an organization-level webhook.

        Org webhooks can be used for attacker persistence (exfiltrating events).
        """
        result = OperationResult(
            operation="delete_org_webhook",
            target=f"org={self._org},hook_id={hook_id}",
            success=True,
        )
        try:
            resp = self._services.delete(f"/orgs/{self._org}/hooks/{hook_id}")
            if resp.status_code in _SUCCESS_CODES:
                result.details["deleted"] = True
                _log.info(log_event("github_ir_response", "delete_org_webhook.success", target=result.target))
            else:
                result.add_error(f"GitHub API error {resp.status_code}: {self._error_body(resp)}")
                _log.warning(log_event("github_ir_response", "delete_org_webhook.error", target=result.target, status=resp.status_code))
        except requests.exceptions.RequestException as exc:
            result.add_error(str(exc))
            _log.error(log_event("github_ir_response", "delete_org_webhook.error", target=result.target, error=str(exc)))
        return result

    def delete_repo_webhook(self, repo: str, hook_id: int) -> OperationResult:
        """
        Delete a repository-level webhook.
        """
        result = OperationResult(
            operation="delete_repo_webhook",
            target=f"org={self._org},repo={repo},hook_id={hook_id}",
            success=True,
        )
        try:
            resp = self._services.delete(f"/repos/{self._org}/{repo}/hooks/{hook_id}")
            if resp.status_code in _SUCCESS_CODES:
                result.details["deleted"] = True
                _log.info(log_event("github_ir_response", "delete_repo_webhook.success", target=result.target))
            else:
                result.add_error(f"GitHub API error {resp.status_code}: {self._error_body(resp)}")
                _log.warning(log_event("github_ir_response", "delete_repo_webhook.error", target=result.target, status=resp.status_code))
        except requests.exceptions.RequestException as exc:
            result.add_error(str(exc))
            _log.error(log_event("github_ir_response", "delete_repo_webhook.error", target=result.target, error=str(exc)))
        return result

    # --------------------
    # Teams
    # --------------------

    def remove_user_from_team(self, team_slug: str, username: str) -> OperationResult:
        """
        Remove a user from an organization team.

        Teams gate repository access. Removing a user from a team revokes all
        repository permissions inherited through that team.
        """
        result = OperationResult(
            operation="remove_user_from_team",
            target=f"org={self._org},team={team_slug},user={username}",
            success=True,
        )
        try:
            resp = self._services.delete(
                f"/orgs/{self._org}/teams/{team_slug}/memberships/{username}"
            )
            if resp.status_code in _SUCCESS_CODES:
                result.details["removed"] = True
                _log.info(log_event("github_ir_response", "remove_user_from_team.success", target=result.target))
            else:
                result.add_error(f"GitHub API error {resp.status_code}: {self._error_body(resp)}")
                _log.warning(log_event("github_ir_response", "remove_user_from_team.error", target=result.target, status=resp.status_code))
        except requests.exceptions.RequestException as exc:
            result.add_error(str(exc))
            _log.error(log_event("github_ir_response", "remove_user_from_team.error", target=result.target, error=str(exc)))
        return result

    # --------------------
    # Actions
    # --------------------

    def disable_actions_workflow(self, repo: str, workflow_id: str) -> OperationResult:
        """
        Disable a GitHub Actions workflow.

        Stops the workflow from running on future trigger events without
        deleting the workflow file. Use list_repo_actions_workflows to find IDs.
        """
        result = OperationResult(
            operation="disable_actions_workflow",
            target=f"org={self._org},repo={repo},workflow={workflow_id}",
            success=True,
        )
        try:
            resp = self._services.put(
                f"/repos/{self._org}/{repo}/actions/workflows/{workflow_id}/disable"
            )
            if resp.status_code in _SUCCESS_CODES:
                result.details["disabled"] = True
                _log.info(log_event("github_ir_response", "disable_actions_workflow.success", target=result.target))
            else:
                result.add_error(f"GitHub API error {resp.status_code}: {self._error_body(resp)}")
                _log.warning(log_event("github_ir_response", "disable_actions_workflow.error", target=result.target, status=resp.status_code))
        except requests.exceptions.RequestException as exc:
            result.add_error(str(exc))
            _log.error(log_event("github_ir_response", "disable_actions_workflow.error", target=result.target, error=str(exc)))
        return result

    def disable_actions_for_repo(self, repo: str) -> OperationResult:
        """
        Disable GitHub Actions entirely for a repository.

        Prevents all workflow execution. Useful when a repo is fully compromised
        and no workflow should run until the investigation is complete.
        """
        result = OperationResult(
            operation="disable_actions_for_repo",
            target=f"org={self._org},repo={repo}",
            success=True,
        )
        try:
            resp = self._services.put(
                f"/repos/{self._org}/{repo}/actions/permissions",
                json={"enabled": False},
            )
            if resp.status_code in _SUCCESS_CODES:
                result.details["disabled"] = True
                _log.info(log_event("github_ir_response", "disable_actions_for_repo.success", target=result.target))
            else:
                result.add_error(f"GitHub API error {resp.status_code}: {self._error_body(resp)}")
                _log.warning(log_event("github_ir_response", "disable_actions_for_repo.error", target=result.target, status=resp.status_code))
        except requests.exceptions.RequestException as exc:
            result.add_error(str(exc))
            _log.error(log_event("github_ir_response", "disable_actions_for_repo.error", target=result.target, error=str(exc)))
        return result

    # --------------------
    # Apps
    # --------------------

    def revoke_github_app_installation(self, installation_id: int) -> OperationResult:
        """
        Uninstall a GitHub App installation from the organization.

        GitHub Apps are a major persistence vector. Revoking the installation
        removes all permissions the app had to org resources.

        Note: requires an org owner token with admin:org scope.
        """
        result = OperationResult(
            operation="revoke_github_app_installation",
            target=f"org={self._org},installation={installation_id}",
            success=True,
        )
        try:
            resp = self._services.delete(
                f"/orgs/{self._org}/installations/{installation_id}"
            )
            if resp.status_code in _SUCCESS_CODES:
                result.details["revoked"] = True
                _log.info(log_event("github_ir_response", "revoke_github_app_installation.success", target=result.target))
            else:
                result.add_error(f"GitHub API error {resp.status_code}: {self._error_body(resp)}")
                _log.warning(log_event("github_ir_response", "revoke_github_app_installation.error", target=result.target, status=resp.status_code))
        except requests.exceptions.RequestException as exc:
            result.add_error(str(exc))
            _log.error(log_event("github_ir_response", "revoke_github_app_installation.error", target=result.target, error=str(exc)))
        return result

    # --------------------
    # Repository
    # --------------------

    def set_repo_visibility_private(self, repo: str) -> OperationResult:
        """
        Make a repository private.

        Immediately removes public read access. Use when a repository has been
        identified as exposing sensitive code or secrets.
        """
        result = OperationResult(
            operation="set_repo_visibility_private",
            target=f"org={self._org},repo={repo}",
            success=True,
        )
        try:
            resp = self._services.patch(
                f"/repos/{self._org}/{repo}",
                json={"private": True, "visibility": "private"},
            )
            if resp.status_code == 200:
                result.details["private"] = True
                result.details["repo"] = resp.json()
                _log.info(log_event("github_ir_response", "set_repo_visibility_private.success", target=result.target))
            else:
                result.add_error(f"GitHub API error {resp.status_code}: {self._error_body(resp)}")
                _log.warning(log_event("github_ir_response", "set_repo_visibility_private.error", target=result.target, status=resp.status_code))
        except requests.exceptions.RequestException as exc:
            result.add_error(str(exc))
            _log.error(log_event("github_ir_response", "set_repo_visibility_private.error", target=result.target, error=str(exc)))
        return result

    def archive_repository(self, repo: str) -> OperationResult:
        """
        Archive a repository, making it read-only.

        Archived repos reject all push operations. This is idempotent —
        archiving an already-archived repo succeeds without error.
        """
        result = OperationResult(
            operation="archive_repository",
            target=f"org={self._org},repo={repo}",
            success=True,
        )
        try:
            resp = self._services.patch(f"/repos/{self._org}/{repo}", json={"archived": True})
            if resp.status_code == 200:
                result.details["archived"] = True
                result.details["repo"] = resp.json()
                _log.info(log_event("github_ir_response", "archive_repository.success", target=result.target))
            else:
                result.add_error(f"GitHub API error {resp.status_code}: {self._error_body(resp)}")
                _log.warning(log_event("github_ir_response", "archive_repository.error", target=result.target, status=resp.status_code))
        except requests.exceptions.RequestException as exc:
            result.add_error(str(exc))
            _log.error(log_event("github_ir_response", "archive_repository.error", target=result.target, error=str(exc)))
        return result
