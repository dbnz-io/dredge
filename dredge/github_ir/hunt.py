from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import requests
import requests.exceptions

from .config import GitHubIRConfig
from .services import GitHubServiceRegistry
from .models import OperationResult
from ..log import get_logger, event as log_event

_log = get_logger(__name__)


_RATE_LIMIT_STATUS = {403, 429}


class GitHubIRHunt:
    """
    Hunt / search utilities over GitHub org audit logs.

    Uses:
        GET /orgs/{org}/audit-log
    """

    def __init__(self, services: GitHubServiceRegistry, config: GitHubIRConfig) -> None:
        self._services = services
        self._config = config

    def search_audit_log(
        self,
        *,
        actor: Optional[str] = None,
        action: Optional[str] = None,
        repo: Optional[str] = None,
        source_ip: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        include: Optional[str] = None,  # "web" | "git" | "all"
        max_events: int = 500,
        per_page: int = 100,
        throttle_max_retries: int = 5,
        throttle_base_delay: float = 1.0,
    ) -> OperationResult:
        """
        Search GitHub org audit log with simple filters.

        Args:
            actor:      GitHub username (actor) filter.
            action:     Audit action, e.g. "repo.create", "org.add_member".
            repo:       Repository filter, e.g. "org/repo".
            source_ip:  IP address filter (actor_ip).
            start_time: Earliest event time (UTC). If set, used in `created:` range.
            end_time:   Latest event time (UTC). If set, used in `created:` range.
            include:    "web" (default), "git", or "all". If None, uses config.include.
            max_events: Max events to return.
            per_page:   GitHub per_page parameter (<=100).
        """
        now = datetime.now(timezone.utc)
        if start_time and start_time.tzinfo is None:
            start_time = start_time.replace(tzinfo=timezone.utc)
        if end_time and end_time.tzinfo is None:
            end_time = end_time.replace(tzinfo=timezone.utc)

        phrase = self._build_phrase(
            actor=actor,
            action=action,
            repo=repo,
            source_ip=source_ip,
            start_time=start_time,
            end_time=end_time,
        )

        result = OperationResult(
            operation="github_search_audit_log",
            target=self._target_string(
                actor=actor,
                action=action,
                repo=repo,
                source_ip=source_ip,
                start_time=start_time,
                end_time=end_time,
            ),
            success=True,
        )

        events: List[Dict[str, Any]] = []
        page = 1
        include_value = include or self._config.include

        while len(events) < max_events:
            params: Dict[str, Any] = {
                "page": page,
                "per_page": min(max(per_page, 1), 100),
                "include": include_value,
            }
            if phrase:
                params["phrase"] = phrase

            try:
                resp = self._call_with_backoff(
                    path=self._services.audit_log_path_base,
                    params=params,
                    throttle_max_retries=throttle_max_retries,
                    throttle_base_delay=throttle_base_delay,
                )
            except (RuntimeError, requests.exceptions.RequestException) as exc:
                result.add_error(f"GitHub audit log API failed: {exc}")
                _log.error(log_event("github_ir_hunt", "search_audit_log.api_error", target=result.target, error=str(exc)))
                break

            page_events = resp.json()
            if not isinstance(page_events, list) or not page_events:
                break

            for ev in page_events:
                if len(events) >= max_events:
                    break
                events.append(self._normalize_event(ev))

            # GitHub org audit log uses standard page-based pagination
            # stop when fewer than requested are returned
            if len(page_events) < params["per_page"]:
                break

            page += 1

        result.details["events"] = events
        result.details["statistics"] = {
            "total_events_returned": len(events),
            "pages_fetched": page,
            "phrase": phrase,
            "include": include_value,
        }

        return result

    # ----------------- internal helpers -----------------

    @staticmethod
    def _target_string(
        *,
        actor: Optional[str],
        action: Optional[str],
        repo: Optional[str],
        source_ip: Optional[str],
        start_time: Optional[datetime],
        end_time: Optional[datetime],
    ) -> str:
        bits = []
        if actor:
            bits.append(f"actor={actor}")
        if action:
            bits.append(f"action={action}")
        if repo:
            bits.append(f"repo={repo}")
        if source_ip:
            bits.append(f"source_ip={source_ip}")
        if start_time or end_time:
            bits.append(
                f"created={start_time.isoformat() if start_time else ''}"
                f"..{end_time.isoformat() if end_time else ''}"
            )
        return ",".join(bits) if bits else "github_audit_log"

    @staticmethod
    def _build_phrase(
        *,
        actor: Optional[str],
        action: Optional[str],
        repo: Optional[str],
        source_ip: Optional[str],
        start_time: Optional[datetime],
        end_time: Optional[datetime],
    ) -> str:
        """
        Build GitHub audit log search phrase.

        Based on GitHub's audit log search syntax: actor:, action:, repo:, created:, etc.:contentReference[oaicite:2]{index=2}
        """
        parts: List[str] = []

        if actor:
            parts.append(f"actor:{actor}")
        if action:
            parts.append(f"action:{action}")
        if repo:
            parts.append(f"repo:{repo}")
        if source_ip:
            # field is usually "actor_ip:"
            parts.append(f"actor_ip:{source_ip}")
        if start_time or end_time:
            def fmt(dt: datetime) -> str:
                # GitHub expects YYYY-MM-DD or full timestamp; keep it simple.
                return dt.date().isoformat()

            if start_time and end_time:
                parts.append(f"created:{fmt(start_time)}..{fmt(end_time)}")
            elif start_time:
                parts.append(f"created:>={fmt(start_time)}")
            elif end_time:
                parts.append(f"created:<={fmt(end_time)}")

        return " ".join(parts)

    @staticmethod
    def _normalize_event(ev: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize a GitHub audit log event into a stable dict.
        """
        return {
            "action": ev.get("action"),
            "actor": ev.get("actor"),
            "actor_ip": ev.get("actor_ip"),
            "repository": ev.get("repo"),
            "org": ev.get("org"),
            "created_at": ev.get("@timestamp") or ev.get("created_at"),
            "raw": ev,
        }

    def _call_with_backoff(
        self,
        *,
        path: str,
        params: Dict[str, Any],
        throttle_max_retries: int,
        throttle_base_delay: float,
    ) -> requests.Response:
        """
        Call GitHub with basic backoff on rate limiting.

        Audit log endpoint has its own rate limit (e.g. 1,750/h).:contentReference[oaicite:3]{index=3}
        """
        attempt = 0
        while True:
            resp = self._services.get(path, params=params)

            # OK
            if 200 <= resp.status_code < 300:
                return resp

            # Handle rate limiting
            if resp.status_code in _RATE_LIMIT_STATUS and attempt < throttle_max_retries:
                reset_header = resp.headers.get("X-RateLimit-Reset")
                remaining_header = resp.headers.get("X-RateLimit-Remaining")

                delay = throttle_base_delay * (2 ** attempt)

                # If the reset time is provided and we're actually at 0 remaining, wait until then.
                if remaining_header == "0" and reset_header:
                    try:
                        reset_epoch = int(reset_header)
                        now = int(time.time())
                        wait = max(reset_epoch - now, delay)
                        _log.warning(log_event("github_ir_hunt", "rate_limit", status=resp.status_code, attempt=attempt, wait=wait))
                        time.sleep(wait)
                    except ValueError:
                        _log.warning(log_event("github_ir_hunt", "rate_limit", status=resp.status_code, attempt=attempt, delay=delay))
                        time.sleep(delay)
                else:
                    _log.warning(log_event("github_ir_hunt", "rate_limit", status=resp.status_code, attempt=attempt, delay=delay))
                    time.sleep(delay)

                attempt += 1
                continue

            # Other errors → raise with context
            try:
                msg = resp.json()
            except ValueError:
                msg = resp.text

            raise RuntimeError(f"GitHub API error {resp.status_code}: {msg}")

    # ---- Generic paginator ----

    def _paginate(
        self,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        max_items: int,
        per_page: int = 100,
        throttle_max_retries: int = 5,
        throttle_base_delay: float = 1.0,
    ) -> List[Dict[str, Any]]:
        """
        Generic paginator using _call_with_backoff.

        Stops when fewer items than per_page are returned (last page) or
        max_items is reached. Raises RuntimeError on non-rate-limit HTTP errors.
        """
        items: List[Dict[str, Any]] = []
        page = 1
        base = {**(params or {}), "per_page": min(per_page, 100)}

        while len(items) < max_items:
            resp = self._call_with_backoff(
                path=path,
                params={**base, "page": page},
                throttle_max_retries=throttle_max_retries,
                throttle_base_delay=throttle_base_delay,
            )
            page_data = resp.json()
            if not isinstance(page_data, list) or not page_data:
                break
            for item in page_data:
                if len(items) >= max_items:
                    break
                items.append(item)
            if len(page_data) < base["per_page"]:
                break
            page += 1

        return items

    # =====================
    # Secret scanning
    # =====================

    def hunt_secret_scanning_alerts(
        self,
        repo: Optional[str] = None,
        *,
        state: str = "open",
        max_alerts: int = 100,
        throttle_max_retries: int = 5,
        throttle_base_delay: float = 1.0,
    ) -> OperationResult:
        """
        List secret scanning alerts for the org or a specific repository.

        Requires GitHub Advanced Security (GHAS). Returns 404/403 for orgs
        or repos without GHAS enabled.

        Args:
            repo:        If provided, queries a single repo. Otherwise queries all org repos.
            state:       Alert state filter: "open" or "resolved" (default "open").
            max_alerts:  Maximum alerts to return.
        """
        result = OperationResult(
            operation="hunt_secret_scanning_alerts",
            target=f"org={self._config.org or 'enterprise'},repo={repo or 'all'},state={state}",
            success=True,
        )

        org = self._config.org
        if not org:
            result.add_error("hunt_secret_scanning_alerts requires org-scoped GitHubIRConfig")
            return result

        path = (
            f"/repos/{org}/{repo}/secret-scanning/alerts"
            if repo
            else f"/orgs/{org}/secret-scanning/alerts"
        )

        try:
            alerts = self._paginate(
                path,
                params={"state": state},
                max_items=max_alerts,
                throttle_max_retries=throttle_max_retries,
                throttle_base_delay=throttle_base_delay,
            )
        except (RuntimeError, requests.exceptions.RequestException) as exc:
            result.add_error(f"GitHub API error: {exc}")
            _log.error(log_event("github_ir_hunt", "hunt_secret_scanning_alerts.error", target=result.target, error=str(exc)))
            alerts = []

        result.details["alerts"] = alerts
        result.details["statistics"] = {"total": len(alerts), "repo": repo, "state": state}
        _log.info(log_event("github_ir_hunt", "hunt_secret_scanning_alerts.complete", target=result.target, total=len(alerts)))
        return result

    # =====================
    # Code scanning
    # =====================

    def hunt_code_scanning_alerts(
        self,
        repo: str,
        *,
        state: str = "open",
        max_alerts: int = 100,
        throttle_max_retries: int = 5,
        throttle_base_delay: float = 1.0,
    ) -> OperationResult:
        """
        List code scanning alerts for a repository.

        Requires GitHub Advanced Security (GHAS).

        Args:
            repo:        Repository name (without org prefix).
            state:       Alert state: "open", "dismissed", "fixed" (default "open").
            max_alerts:  Maximum alerts to return.
        """
        result = OperationResult(
            operation="hunt_code_scanning_alerts",
            target=f"org={self._config.org or 'enterprise'},repo={repo},state={state}",
            success=True,
        )

        org = self._config.org
        if not org:
            result.add_error("hunt_code_scanning_alerts requires org-scoped GitHubIRConfig")
            return result

        try:
            alerts = self._paginate(
                f"/repos/{org}/{repo}/code-scanning/alerts",
                params={"state": state},
                max_items=max_alerts,
                throttle_max_retries=throttle_max_retries,
                throttle_base_delay=throttle_base_delay,
            )
        except (RuntimeError, requests.exceptions.RequestException) as exc:
            result.add_error(f"GitHub API error: {exc}")
            _log.error(log_event("github_ir_hunt", "hunt_code_scanning_alerts.error", target=result.target, error=str(exc)))
            alerts = []

        result.details["alerts"] = alerts
        result.details["statistics"] = {"total": len(alerts), "repo": repo, "state": state}
        _log.info(log_event("github_ir_hunt", "hunt_code_scanning_alerts.complete", target=result.target, total=len(alerts)))
        return result

    # =====================
    # Org members
    # =====================

    def list_org_members(
        self,
        *,
        role: Optional[str] = None,
        max_members: int = 500,
        throttle_max_retries: int = 5,
        throttle_base_delay: float = 1.0,
    ) -> OperationResult:
        """
        List all members of the organization.

        Useful for auditing who currently has org access.

        Args:
            role:        Filter by role: "member", "admin". Omit for all members.
            max_members: Maximum members to return.
        """
        result = OperationResult(
            operation="list_org_members",
            target=f"org={self._config.org or 'enterprise'},role={role or 'all'}",
            success=True,
        )

        org = self._config.org
        if not org:
            result.add_error("list_org_members requires org-scoped GitHubIRConfig")
            return result

        params: Dict[str, Any] = {}
        if role:
            params["role"] = role

        try:
            members = self._paginate(
                f"/orgs/{org}/members",
                params=params,
                max_items=max_members,
                throttle_max_retries=throttle_max_retries,
                throttle_base_delay=throttle_base_delay,
            )
        except (RuntimeError, requests.exceptions.RequestException) as exc:
            result.add_error(f"GitHub API error: {exc}")
            _log.error(log_event("github_ir_hunt", "list_org_members.error", target=result.target, error=str(exc)))
            members = []

        result.details["members"] = members
        result.details["statistics"] = {"total": len(members), "role": role or "all"}
        _log.info(log_event("github_ir_hunt", "list_org_members.complete", target=result.target, total=len(members)))
        return result

    def list_outside_collaborators(
        self,
        *,
        max_items: int = 200,
        throttle_max_retries: int = 5,
        throttle_base_delay: float = 1.0,
    ) -> OperationResult:
        """
        List users who have repository access but are not org members.

        Outside collaborators are a common lateral movement vector — external
        contractors or bots that retain repo access after their engagement ends.
        """
        result = OperationResult(
            operation="list_outside_collaborators",
            target=f"org={self._config.org or 'enterprise'}",
            success=True,
        )

        org = self._config.org
        if not org:
            result.add_error("list_outside_collaborators requires org-scoped GitHubIRConfig")
            return result

        try:
            collaborators = self._paginate(
                f"/orgs/{org}/outside_collaborators",
                max_items=max_items,
                throttle_max_retries=throttle_max_retries,
                throttle_base_delay=throttle_base_delay,
            )
        except (RuntimeError, requests.exceptions.RequestException) as exc:
            result.add_error(f"GitHub API error: {exc}")
            _log.error(log_event("github_ir_hunt", "list_outside_collaborators.error", target=result.target, error=str(exc)))
            collaborators = []

        result.details["collaborators"] = collaborators
        result.details["statistics"] = {"total": len(collaborators)}
        _log.info(log_event("github_ir_hunt", "list_outside_collaborators.complete", target=result.target, total=len(collaborators)))
        return result

    # =====================
    # Deploy keys
    # =====================

    def list_deploy_keys(
        self,
        repo: str,
        *,
        max_keys: int = 100,
        throttle_max_retries: int = 5,
        throttle_base_delay: float = 1.0,
    ) -> OperationResult:
        """
        List deploy keys for a repository.

        Each key includes its id (needed for revoke_deploy_key), title,
        public key material, created_at, and read_only flag.

        Args:
            repo:     Repository name (without org prefix).
            max_keys: Maximum keys to return.
        """
        result = OperationResult(
            operation="list_deploy_keys",
            target=f"org={self._config.org or 'enterprise'},repo={repo}",
            success=True,
        )

        org = self._config.org
        if not org:
            result.add_error("list_deploy_keys requires org-scoped GitHubIRConfig")
            return result

        try:
            keys = self._paginate(
                f"/repos/{org}/{repo}/keys",
                max_items=max_keys,
                throttle_max_retries=throttle_max_retries,
                throttle_base_delay=throttle_base_delay,
            )
        except (RuntimeError, requests.exceptions.RequestException) as exc:
            result.add_error(f"GitHub API error: {exc}")
            _log.error(log_event("github_ir_hunt", "list_deploy_keys.error", target=result.target, error=str(exc)))
            keys = []

        result.details["keys"] = keys
        result.details["statistics"] = {"total": len(keys), "repo": repo}
        _log.info(log_event("github_ir_hunt", "list_deploy_keys.complete", target=result.target, total=len(keys)))
        return result

    # =====================
    # GitHub Apps
    # =====================

    def list_github_apps(
        self,
        *,
        max_items: int = 200,
        throttle_max_retries: int = 5,
        throttle_base_delay: float = 1.0,
    ) -> OperationResult:
        """
        List all GitHub App installations on the organization.

        Apps are a major lateral movement and persistence vector. Each entry
        includes the app name, permissions, and the repositories it can access.
        """
        result = OperationResult(
            operation="list_github_apps",
            target=f"org={self._config.org or 'enterprise'}",
            success=True,
        )

        org = self._config.org
        if not org:
            result.add_error("list_github_apps requires org-scoped GitHubIRConfig")
            return result

        try:
            installations = self._paginate(
                f"/orgs/{org}/installations",
                max_items=max_items,
                throttle_max_retries=throttle_max_retries,
                throttle_base_delay=throttle_base_delay,
            )
        except (RuntimeError, requests.exceptions.RequestException) as exc:
            result.add_error(f"GitHub API error: {exc}")
            _log.error(log_event("github_ir_hunt", "list_github_apps.error", target=result.target, error=str(exc)))
            installations = []

        result.details["installations"] = installations
        result.details["statistics"] = {"total": len(installations)}
        _log.info(log_event("github_ir_hunt", "list_github_apps.complete", target=result.target, total=len(installations)))
        return result

    # =====================
    # Actions workflow runs
    # =====================

    def list_actions_workflow_runs(
        self,
        repo: str,
        *,
        workflow_id: Optional[str] = None,
        status: Optional[str] = None,
        max_runs: int = 100,
        throttle_max_retries: int = 5,
        throttle_base_delay: float = 1.0,
    ) -> OperationResult:
        """
        List GitHub Actions workflow runs for a repository.

        Useful for spotting unexpected or attacker-triggered runs, especially
        on protected branches or outside normal working hours.

        Args:
            repo:        Repository name (without org prefix).
            workflow_id: Optional workflow file name or ID to filter runs.
            status:      Filter by status: "completed", "in_progress", "queued", etc.
            max_runs:    Maximum runs to return.
        """
        result = OperationResult(
            operation="list_actions_workflow_runs",
            target=f"org={self._config.org or 'enterprise'},repo={repo}",
            success=True,
        )

        org = self._config.org
        if not org:
            result.add_error("list_actions_workflow_runs requires org-scoped GitHubIRConfig")
            return result

        if workflow_id:
            path = f"/repos/{org}/{repo}/actions/workflows/{workflow_id}/runs"
        else:
            path = f"/repos/{org}/{repo}/actions/runs"

        params: Dict[str, Any] = {}
        if status:
            params["status"] = status

        try:
            runs = self._paginate(
                path,
                params=params if params else None,
                max_items=max_runs,
                throttle_max_retries=throttle_max_retries,
                throttle_base_delay=throttle_base_delay,
            )
        except (RuntimeError, requests.exceptions.RequestException) as exc:
            result.add_error(f"GitHub API error: {exc}")
            _log.error(log_event("github_ir_hunt", "list_actions_workflow_runs.error", target=result.target, error=str(exc)))
            runs = []

        result.details["runs"] = runs
        result.details["statistics"] = {"total": len(runs), "repo": repo}
        _log.info(log_event("github_ir_hunt", "list_actions_workflow_runs.complete", target=result.target, total=len(runs)))
        return result

    # =====================
    # Teams
    # =====================

    def list_org_teams(
        self,
        *,
        max_teams: int = 200,
        throttle_max_retries: int = 5,
        throttle_base_delay: float = 1.0,
    ) -> OperationResult:
        """
        List all teams in the organization.

        Teams control repository access. Enumerating them reveals the full
        access structure and identifies teams with broad permissions.
        """
        result = OperationResult(
            operation="list_org_teams",
            target=f"org={self._config.org or 'enterprise'}",
            success=True,
        )

        org = self._config.org
        if not org:
            result.add_error("list_org_teams requires org-scoped GitHubIRConfig")
            return result

        try:
            teams = self._paginate(
                f"/orgs/{org}/teams",
                max_items=max_teams,
                throttle_max_retries=throttle_max_retries,
                throttle_base_delay=throttle_base_delay,
            )
        except (RuntimeError, requests.exceptions.RequestException) as exc:
            result.add_error(f"GitHub API error: {exc}")
            _log.error(log_event("github_ir_hunt", "list_org_teams.error", target=result.target, error=str(exc)))
            teams = []

        result.details["teams"] = teams
        result.details["statistics"] = {"total": len(teams)}
        _log.info(log_event("github_ir_hunt", "list_org_teams.complete", target=result.target, total=len(teams)))
        return result

    def list_team_members(
        self,
        team_slug: str,
        *,
        role: Optional[str] = None,
        max_members: int = 200,
        throttle_max_retries: int = 5,
        throttle_base_delay: float = 1.0,
    ) -> OperationResult:
        """
        List members of an organization team.

        Args:
            team_slug:   Team slug (from list_org_teams).
            role:        Filter by role: "member" or "maintainer". Omit for all.
            max_members: Maximum members to return.
        """
        result = OperationResult(
            operation="list_team_members",
            target=f"org={self._config.org or 'enterprise'},team={team_slug}",
            success=True,
        )

        org = self._config.org
        if not org:
            result.add_error("list_team_members requires org-scoped GitHubIRConfig")
            return result

        params: Dict[str, Any] = {}
        if role:
            params["role"] = role

        try:
            members = self._paginate(
                f"/orgs/{org}/teams/{team_slug}/members",
                params=params if params else None,
                max_items=max_members,
                throttle_max_retries=throttle_max_retries,
                throttle_base_delay=throttle_base_delay,
            )
        except (RuntimeError, requests.exceptions.RequestException) as exc:
            result.add_error(f"GitHub API error: {exc}")
            _log.error(log_event("github_ir_hunt", "list_team_members.error", target=result.target, error=str(exc)))
            members = []

        result.details["members"] = members
        result.details["statistics"] = {"total": len(members), "team": team_slug}
        _log.info(log_event("github_ir_hunt", "list_team_members.complete", target=result.target, total=len(members)))
        return result

    # =====================
    # Actions secrets
    # =====================

    def list_actions_secrets(
        self,
        repo: Optional[str] = None,
        *,
        max_secrets: int = 200,
        throttle_max_retries: int = 5,
        throttle_base_delay: float = 1.0,
    ) -> OperationResult:
        """
        List GitHub Actions secret names for the org or a specific repository.

        Secret values are never returned by the API. This method returns names
        only, which is sufficient to spot injected or unexpected secrets.

        Args:
            repo: If provided, list repo-level secrets. Otherwise list org secrets.
        """
        result = OperationResult(
            operation="list_actions_secrets",
            target=f"org={self._config.org or 'enterprise'},repo={repo or 'org'}",
            success=True,
        )

        org = self._config.org
        if not org:
            result.add_error("list_actions_secrets requires org-scoped GitHubIRConfig")
            return result

        path = (
            f"/repos/{org}/{repo}/actions/secrets"
            if repo
            else f"/orgs/{org}/actions/secrets"
        )

        try:
            secrets = self._paginate(
                path,
                max_items=max_secrets,
                throttle_max_retries=throttle_max_retries,
                throttle_base_delay=throttle_base_delay,
            )
        except (RuntimeError, requests.exceptions.RequestException) as exc:
            result.add_error(f"GitHub API error: {exc}")
            _log.error(log_event("github_ir_hunt", "list_actions_secrets.error", target=result.target, error=str(exc)))
            secrets = []

        result.details["secrets"] = secrets
        result.details["statistics"] = {"total": len(secrets)}
        _log.info(log_event("github_ir_hunt", "list_actions_secrets.complete", target=result.target, total=len(secrets)))
        return result

    # =====================
    # Repo environments
    # =====================

    def list_repo_environments(
        self,
        repo: str,
        *,
        max_items: int = 100,
        throttle_max_retries: int = 5,
        throttle_base_delay: float = 1.0,
    ) -> OperationResult:
        """
        List GitHub Actions deployment environments for a repository.

        Environments have protection rules and environment-scoped secrets.
        Attackers bypass environment protection rules to deploy to production
        without required approvals.

        Args:
            repo: Repository name (without org prefix).
        """
        result = OperationResult(
            operation="list_repo_environments",
            target=f"org={self._config.org or 'enterprise'},repo={repo}",
            success=True,
        )

        org = self._config.org
        if not org:
            result.add_error("list_repo_environments requires org-scoped GitHubIRConfig")
            return result

        try:
            environments = self._paginate(
                f"/repos/{org}/{repo}/environments",
                max_items=max_items,
                throttle_max_retries=throttle_max_retries,
                throttle_base_delay=throttle_base_delay,
            )
        except (RuntimeError, requests.exceptions.RequestException) as exc:
            result.add_error(f"GitHub API error: {exc}")
            _log.error(log_event("github_ir_hunt", "list_repo_environments.error", target=result.target, error=str(exc)))
            environments = []

        result.details["environments"] = environments
        result.details["statistics"] = {"total": len(environments), "repo": repo}
        _log.info(log_event("github_ir_hunt", "list_repo_environments.complete", target=result.target, total=len(environments)))
        return result
