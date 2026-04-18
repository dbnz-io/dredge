import os
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

from unittest.mock import MagicMock, patch
import pytest

from dredge.github_ir.config import GitHubIRConfig
from dredge.github_ir.services import GitHubServiceRegistry


class TestGitHubIRConfig:
    def test_org_only_valid(self):
        cfg = GitHubIRConfig(org="my-org", token="tok")
        assert cfg.org == "my-org"

    def test_enterprise_only_valid(self):
        cfg = GitHubIRConfig(enterprise="my-enterprise", token="tok")
        assert cfg.enterprise == "my-enterprise"

    def test_both_org_and_enterprise_raises(self):
        with pytest.raises(ValueError, match="exactly one"):
            GitHubIRConfig(org="o", enterprise="e", token="tok")

    def test_neither_org_nor_enterprise_raises(self):
        with pytest.raises(ValueError, match="exactly one"):
            GitHubIRConfig(token="tok")

    def test_resolve_token_explicit(self):
        cfg = GitHubIRConfig(org="o", token="my-token")
        assert cfg.resolve_token() == "my-token"

    def test_resolve_token_from_provider(self):
        provider = MagicMock(return_value="provider-token")
        cfg = GitHubIRConfig(org="o", token_provider=provider)
        assert cfg.resolve_token() == "provider-token"

    def test_resolve_token_empty_provider_raises(self):
        provider = MagicMock(return_value="")
        cfg = GitHubIRConfig(org="o", token_provider=provider)
        with pytest.raises(ValueError, match="empty token"):
            cfg.resolve_token()

    def test_resolve_token_from_env_var(self):
        cfg = GitHubIRConfig(org="o", token_env_var="MY_GH_TOKEN")
        with patch.dict(os.environ, {"MY_GH_TOKEN": "env-token"}):
            assert cfg.resolve_token() == "env-token"

    def test_resolve_token_no_source_raises(self):
        cfg = GitHubIRConfig(org="o", token_env_var="MISSING_TOKEN_VAR_XYZ")
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("MISSING_TOKEN_VAR_XYZ", None)
            with pytest.raises(ValueError, match="No GitHub token"):
                cfg.resolve_token()


class TestGitHubServiceRegistry:
    def test_audit_log_path_org(self):
        cfg = GitHubIRConfig(org="solidarity-labs", token="tok")
        reg = GitHubServiceRegistry(cfg)
        assert reg.audit_log_path_base == "/orgs/solidarity-labs/audit-log"

    def test_audit_log_path_enterprise(self):
        cfg = GitHubIRConfig(enterprise="solidarity-enterprise", token="tok")
        reg = GitHubServiceRegistry(cfg)
        assert reg.audit_log_path_base == "/enterprises/solidarity-enterprise/audit-log"

    def test_get_method_makes_http_request(self):
        cfg = GitHubIRConfig(org="o", token="tok")
        reg = GitHubServiceRegistry(cfg)

        mock_session = MagicMock()
        reg._session = mock_session

        reg.get("/orgs/o/audit-log", params={"page": 1})

        mock_session.get.assert_called_once_with(
            "https://api.github.com/orgs/o/audit-log",
            params={"page": 1},
        )
