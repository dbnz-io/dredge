import os
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

from unittest.mock import MagicMock
import pytest
import requests.exceptions

from dredge.github_ir.forensics import GitHubIRForensics
from dredge.github_ir.config import GitHubIRConfig
from dredge.github_ir.services import GitHubServiceRegistry


class FakeResponse:
    def __init__(self, status_code, json_data=None, headers=None):
        self.status_code = status_code
        self._json_data = json_data if json_data is not None else {}
        self.headers = headers or {}
        self.text = str(json_data or "")

    def json(self):
        return self._json_data


def _make_forensics(org="test-org") -> tuple:
    cfg = GitHubIRConfig(org=org, token="tok")
    svc = MagicMock(spec=GitHubServiceRegistry)
    forensics = GitHubIRForensics(svc, cfg)
    return forensics, svc


def _enterprise_forensics() -> GitHubIRForensics:
    cfg = GitHubIRConfig(enterprise="acme", token="tok")
    svc = MagicMock(spec=GitHubServiceRegistry)
    return GitHubIRForensics(svc, cfg)


# ---- get_org_settings ----

class TestGetOrgSettings:
    def test_success_200(self):
        forensics, svc = _make_forensics()
        org_data = {"login": "test-org", "two_factor_requirement_enabled": True}
        svc.get.return_value = FakeResponse(200, org_data)

        result = forensics.get_org_settings()

        assert result.success is True
        assert result.details["org"]["login"] == "test-org"
        svc.get.assert_called_once_with("/orgs/test-org")

    def test_http_error_recorded(self):
        forensics, svc = _make_forensics()
        svc.get.return_value = FakeResponse(404, {"message": "Not Found"})

        result = forensics.get_org_settings()

        assert result.success is False
        assert result.errors

    def test_network_error_recorded(self):
        forensics, svc = _make_forensics()
        svc.get.side_effect = requests.exceptions.ConnectionError("no connection")

        result = forensics.get_org_settings()

        assert result.success is False
        assert "no connection" in result.errors[0]

    def test_enterprise_config_raises(self):
        with pytest.raises(RuntimeError, match="org-scoped"):
            _enterprise_forensics().get_org_settings()


# ---- get_repo_metadata ----

class TestGetRepoMetadata:
    def test_success_200(self):
        forensics, svc = _make_forensics()
        repo_data = {"name": "my-repo", "private": True, "archived": False}
        svc.get.return_value = FakeResponse(200, repo_data)

        result = forensics.get_repo_metadata("my-repo")

        assert result.success is True
        assert result.details["repo"]["name"] == "my-repo"
        svc.get.assert_called_once_with("/repos/test-org/my-repo")

    def test_http_error_recorded(self):
        forensics, svc = _make_forensics()
        svc.get.return_value = FakeResponse(404, {"message": "Not Found"})

        result = forensics.get_repo_metadata("gone-repo")

        assert result.success is False

    def test_network_error_recorded(self):
        forensics, svc = _make_forensics()
        svc.get.side_effect = requests.exceptions.Timeout("timed out")

        result = forensics.get_repo_metadata("repo")

        assert result.success is False
        assert "timed out" in result.errors[0]


# ---- list_repo_collaborators ----

class TestListRepoCollaborators:
    def test_success(self):
        forensics, svc = _make_forensics()
        collabs = [{"login": "alice"}, {"login": "bob"}]
        svc.get.return_value = FakeResponse(200, collabs)

        result = forensics.list_repo_collaborators("my-repo")

        assert result.success is True
        assert len(result.details["collaborators"]) == 2
        assert result.details["statistics"]["total"] == 2
        called_path = svc.get.call_args[0][0]
        assert called_path == "/repos/test-org/my-repo/collaborators"

    def test_pagination_collects_multiple_pages(self):
        forensics, svc = _make_forensics()
        page1 = [{"login": f"u{i}"} for i in range(100)]
        page2 = [{"login": f"u{i}"} for i in range(100, 120)]

        svc.get.side_effect = [
            FakeResponse(200, page1),
            FakeResponse(200, page2),
        ]

        result = forensics.list_repo_collaborators("repo")

        assert len(result.details["collaborators"]) == 120
        assert svc.get.call_count == 2

    def test_http_error_recorded(self):
        forensics, svc = _make_forensics()
        svc.get.return_value = FakeResponse(403, {"message": "Forbidden"})

        result = forensics.list_repo_collaborators("repo")

        assert result.success is False

    def test_max_items_respected(self):
        forensics, svc = _make_forensics()
        collabs = [{"login": f"u{i}"} for i in range(100)]
        svc.get.return_value = FakeResponse(200, collabs)

        result = forensics.list_repo_collaborators("repo", max_items=10)

        assert len(result.details["collaborators"]) == 10


# ---- get_branch_protection ----

class TestGetBranchProtection:
    def test_success_200_protected(self):
        forensics, svc = _make_forensics()
        protection = {"required_status_checks": {"strict": True}}
        svc.get.return_value = FakeResponse(200, protection)

        result = forensics.get_branch_protection("repo", "main")

        assert result.success is True
        assert result.details["protected"] is True
        assert result.details["protection"] == protection
        svc.get.assert_called_once_with("/repos/test-org/repo/branches/main/protection")

    def test_404_means_unprotected_not_error(self):
        forensics, svc = _make_forensics()
        svc.get.return_value = FakeResponse(404, {"message": "Branch not protected"})

        result = forensics.get_branch_protection("repo", "main")

        assert result.success is True
        assert result.details["protected"] is False
        assert result.details["protection"] is None
        assert not result.errors

    def test_403_is_failure(self):
        forensics, svc = _make_forensics()
        svc.get.return_value = FakeResponse(403, {"message": "Forbidden"})

        result = forensics.get_branch_protection("repo", "main")

        assert result.success is False
        assert result.errors

    def test_network_error_recorded(self):
        forensics, svc = _make_forensics()
        svc.get.side_effect = requests.exceptions.ConnectionError("err")

        result = forensics.get_branch_protection("repo", "main")

        assert result.success is False
        assert result.errors


# ---- list_org_webhooks ----

class TestListOrgWebhooks:
    def test_success(self):
        forensics, svc = _make_forensics()
        hooks = [{"id": 1, "config": {"url": "https://example.com"}}, {"id": 2, "config": {"url": "https://other.com"}}]
        svc.get.return_value = FakeResponse(200, hooks)

        result = forensics.list_org_webhooks()

        assert result.success is True
        assert len(result.details["webhooks"]) == 2
        assert result.details["statistics"]["total"] == 2
        called_path = svc.get.call_args[0][0]
        assert called_path == "/orgs/test-org/hooks"

    def test_http_error_recorded(self):
        forensics, svc = _make_forensics()
        svc.get.return_value = FakeResponse(403, {"message": "Forbidden"})

        result = forensics.list_org_webhooks()

        assert result.success is False

    def test_empty_list_success(self):
        forensics, svc = _make_forensics()
        svc.get.return_value = FakeResponse(200, [])

        result = forensics.list_org_webhooks()

        assert result.success is True
        assert result.details["webhooks"] == []


# ---- list_repo_webhooks ----

class TestListRepoWebhooks:
    def test_success(self):
        forensics, svc = _make_forensics()
        hooks = [{"id": 7, "config": {"url": "https://ci.example.com"}}]
        svc.get.return_value = FakeResponse(200, hooks)

        result = forensics.list_repo_webhooks("my-repo")

        assert result.success is True
        assert len(result.details["webhooks"]) == 1
        assert result.details["statistics"]["repo"] == "my-repo"
        called_path = svc.get.call_args[0][0]
        assert called_path == "/repos/test-org/my-repo/hooks"

    def test_http_error_recorded(self):
        forensics, svc = _make_forensics()
        svc.get.return_value = FakeResponse(404, {"message": "Not Found"})

        result = forensics.list_repo_webhooks("gone-repo")

        assert result.success is False

    def test_pagination_collects_multiple_pages(self):
        forensics, svc = _make_forensics()
        page1 = [{"id": i} for i in range(100)]
        page2 = [{"id": i} for i in range(100, 115)]

        svc.get.side_effect = [
            FakeResponse(200, page1),
            FakeResponse(200, page2),
        ]

        result = forensics.list_repo_webhooks("repo")

        assert len(result.details["webhooks"]) == 115
