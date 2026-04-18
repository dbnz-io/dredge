import os
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

from unittest.mock import MagicMock
import pytest
import requests.exceptions

from dredge.github_ir.response import GitHubIRResponse
from dredge.github_ir.config import GitHubIRConfig
from dredge.github_ir.services import GitHubServiceRegistry


class FakeResponse:
    def __init__(self, status_code, json_data=None, headers=None):
        self.status_code = status_code
        self._json_data = json_data or {}
        self.headers = headers or {}
        self.text = str(json_data or "")

    def json(self):
        return self._json_data


def _make_services(status=204, json_data=None):
    """Return a MagicMock services object with all HTTP methods returning the given status."""
    svc = MagicMock(spec=GitHubServiceRegistry)
    resp = FakeResponse(status, json_data)
    svc.put.return_value = resp
    svc.delete.return_value = resp
    svc.patch.return_value = resp
    return svc


def _make_response(org="test-org") -> GitHubIRResponse:
    cfg = GitHubIRConfig(org=org, token="tok")
    svc = _make_services()
    return GitHubIRResponse(svc, cfg)


def _enterprise_response() -> GitHubIRResponse:
    cfg = GitHubIRConfig(enterprise="acme", token="tok")
    svc = _make_services()
    return GitHubIRResponse(svc, cfg)


# ---- block_org_member ----

class TestBlockOrgMember:
    def test_success_204(self):
        cfg = GitHubIRConfig(org="test-org", token="tok")
        svc = _make_services(status=204)
        result = GitHubIRResponse(svc, cfg).block_org_member("evil")
        assert result.success is True
        assert result.details["blocked"] is True
        svc.put.assert_called_once_with("/orgs/test-org/blocks/evil")

    def test_http_error_recorded(self):
        cfg = GitHubIRConfig(org="test-org", token="tok")
        svc = _make_services(status=422, json_data={"message": "unprocessable"})
        result = GitHubIRResponse(svc, cfg).block_org_member("x")
        assert result.success is False
        assert result.errors

    def test_network_error_recorded(self):
        cfg = GitHubIRConfig(org="test-org", token="tok")
        svc = _make_services()
        svc.put.side_effect = requests.exceptions.ConnectionError("timeout")
        result = GitHubIRResponse(svc, cfg).block_org_member("x")
        assert result.success is False
        assert "timeout" in result.errors[0]

    def test_enterprise_config_raises(self):
        with pytest.raises(RuntimeError, match="org-scoped"):
            _enterprise_response().block_org_member("x")


# ---- remove_org_member ----

class TestRemoveOrgMember:
    def test_success_204(self):
        cfg = GitHubIRConfig(org="test-org", token="tok")
        svc = _make_services(status=204)
        result = GitHubIRResponse(svc, cfg).remove_org_member("alice")
        assert result.success is True
        assert result.details["removed"] is True
        svc.delete.assert_called_once_with("/orgs/test-org/members/alice")

    def test_http_error_recorded(self):
        cfg = GitHubIRConfig(org="test-org", token="tok")
        svc = _make_services(status=404)
        result = GitHubIRResponse(svc, cfg).remove_org_member("alice")
        assert result.success is False

    def test_network_error_recorded(self):
        cfg = GitHubIRConfig(org="test-org", token="tok")
        svc = _make_services()
        svc.delete.side_effect = requests.exceptions.ConnectionError("err")
        result = GitHubIRResponse(svc, cfg).remove_org_member("alice")
        assert result.success is False


# ---- remove_repo_collaborator ----

class TestRemoveRepoCollaborator:
    def test_success_204(self):
        cfg = GitHubIRConfig(org="test-org", token="tok")
        svc = _make_services(status=204)
        result = GitHubIRResponse(svc, cfg).remove_repo_collaborator("my-repo", "bob")
        assert result.success is True
        assert result.details["removed"] is True
        svc.delete.assert_called_once_with("/repos/test-org/my-repo/collaborators/bob")

    def test_422_for_org_member_recorded(self):
        cfg = GitHubIRConfig(org="test-org", token="tok")
        svc = _make_services(status=422)
        result = GitHubIRResponse(svc, cfg).remove_repo_collaborator("repo", "member-user")
        assert result.success is False

    def test_enterprise_config_raises(self):
        with pytest.raises(RuntimeError):
            _enterprise_response().remove_repo_collaborator("repo", "user")


# ---- revoke_deploy_key ----

class TestRevokeDeployKey:
    def test_success_204(self):
        cfg = GitHubIRConfig(org="test-org", token="tok")
        svc = _make_services(status=204)
        result = GitHubIRResponse(svc, cfg).revoke_deploy_key("repo", 12345)
        assert result.success is True
        assert result.details["revoked"] is True
        svc.delete.assert_called_once_with("/repos/test-org/repo/keys/12345")

    def test_key_id_is_integer_in_path(self):
        cfg = GitHubIRConfig(org="o", token="t")
        svc = _make_services(204)
        GitHubIRResponse(svc, cfg).revoke_deploy_key("r", 999)
        path = svc.delete.call_args[0][0]
        assert "/keys/999" in path

    def test_http_error_recorded(self):
        cfg = GitHubIRConfig(org="test-org", token="tok")
        svc = _make_services(status=404)
        result = GitHubIRResponse(svc, cfg).revoke_deploy_key("repo", 1)
        assert result.success is False


# ---- delete_org_webhook ----

class TestDeleteOrgWebhook:
    def test_success_204(self):
        cfg = GitHubIRConfig(org="test-org", token="tok")
        svc = _make_services(status=204)
        result = GitHubIRResponse(svc, cfg).delete_org_webhook(42)
        assert result.success is True
        assert result.details["deleted"] is True
        svc.delete.assert_called_once_with("/orgs/test-org/hooks/42")

    def test_http_error_recorded(self):
        cfg = GitHubIRConfig(org="test-org", token="tok")
        svc = _make_services(status=404)
        result = GitHubIRResponse(svc, cfg).delete_org_webhook(99)
        assert result.success is False


# ---- delete_repo_webhook ----

class TestDeleteRepoWebhook:
    def test_success_204(self):
        cfg = GitHubIRConfig(org="test-org", token="tok")
        svc = _make_services(status=204)
        result = GitHubIRResponse(svc, cfg).delete_repo_webhook("repo", 7)
        assert result.success is True
        svc.delete.assert_called_once_with("/repos/test-org/repo/hooks/7")

    def test_http_error_recorded(self):
        cfg = GitHubIRConfig(org="test-org", token="tok")
        svc = _make_services(status=403)
        result = GitHubIRResponse(svc, cfg).delete_repo_webhook("repo", 7)
        assert result.success is False


# ---- archive_repository ----

class TestArchiveRepository:
    def test_success_200_stores_repo_payload(self):
        cfg = GitHubIRConfig(org="test-org", token="tok")
        svc = _make_services(status=200, json_data={"name": "my-repo", "archived": True})
        result = GitHubIRResponse(svc, cfg).archive_repository("my-repo")
        assert result.success is True
        assert result.details["archived"] is True
        assert result.details["repo"]["name"] == "my-repo"
        svc.patch.assert_called_once_with("/repos/test-org/my-repo", json={"archived": True})

    def test_already_archived_is_success(self):
        cfg = GitHubIRConfig(org="test-org", token="tok")
        svc = _make_services(status=200, json_data={"archived": True})
        result = GitHubIRResponse(svc, cfg).archive_repository("already-archived")
        assert result.success is True

    def test_http_error_recorded(self):
        cfg = GitHubIRConfig(org="test-org", token="tok")
        svc = _make_services(status=404)
        result = GitHubIRResponse(svc, cfg).archive_repository("gone")
        assert result.success is False

    def test_network_error_recorded(self):
        cfg = GitHubIRConfig(org="test-org", token="tok")
        svc = _make_services()
        svc.patch.side_effect = requests.exceptions.Timeout("timed out")
        result = GitHubIRResponse(svc, cfg).archive_repository("repo")
        assert result.success is False
        assert "timed out" in result.errors[0]

    def test_enterprise_config_raises(self):
        with pytest.raises(RuntimeError):
            _enterprise_response().archive_repository("repo")
