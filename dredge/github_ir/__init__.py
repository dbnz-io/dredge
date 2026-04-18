from __future__ import annotations

from .config import GitHubIRConfig
from .services import GitHubServiceRegistry
from .hunt import GitHubIRHunt
from .response import GitHubIRResponse
from .forensics import GitHubIRForensics


class GitHubIRNamespace:
    """
    Grouping for GitHub Incident Response functionality.

        dredge.github_ir.hunt.search_audit_log(...)
        dredge.github_ir.response.block_org_member(...)
        dredge.github_ir.forensics.get_org_settings()
    """

    def __init__(self, config: GitHubIRConfig) -> None:
        self._services = GitHubServiceRegistry(config)
        self.hunt = GitHubIRHunt(self._services, config)
        self.response = GitHubIRResponse(self._services, config)
        self.forensics = GitHubIRForensics(self._services, config)
