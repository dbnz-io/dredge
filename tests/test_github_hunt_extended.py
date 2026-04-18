import os
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

from unittest.mock import MagicMock, patch, call
import pytest
import requests.exceptions

from dredge.github_ir.hunt import GitHubIRHunt
from dredge.github_ir.config import GitHubIRConfig
from dredge.github_ir.services import GitHubServiceRegistry


class FakeResponse:
    def __init__(self, status_code, json_data=None, headers=None):
        self.status_code = status_code
        self._json_data = json_data if json_data is not None else []
        self.headers = headers or {}
        self.text = str(json_data or "")

    def json(self):
        return self._json_data


def _make_hunt(org="test-org") -> GitHubIRHunt:
    cfg = GitHubIRConfig(org=org, token="tok")
    svc = MagicMock(spec=GitHubServiceRegistry)
    svc.audit_log_path_base = "/orgs/test-org/audit-log"
    hunt = GitHubIRHunt(svc, cfg)
    return hunt, svc


def _enterprise_hunt() -> GitHubIRHunt:
    cfg = GitHubIRConfig(enterprise="acme", token="tok")
    svc = MagicMock(spec=GitHubServiceRegistry)
    hunt = GitHubIRHunt(svc, cfg)
    return hunt


# ---- _paginate helper ----

class TestPaginate:
    def test_single_page_returned(self):
        hunt, svc = _make_hunt()
        items = [{"id": 1}, {"id": 2}]
        svc.get.return_value = FakeResponse(200, items)

        result = hunt._paginate("/orgs/test-org/members", max_items=100)

        assert result == items
        svc.get.assert_called_once()

    def test_pagination_collects_multiple_pages(self):
        hunt, svc = _make_hunt()
        page1 = [{"id": i} for i in range(100)]
        page2 = [{"id": i} for i in range(100, 140)]

        svc.get.side_effect = [
            FakeResponse(200, page1),
            FakeResponse(200, page2),
        ]

        result = hunt._paginate("/orgs/test-org/members", max_items=500)

        assert len(result) == 140
        assert svc.get.call_count == 2

    def test_max_items_respected(self):
        hunt, svc = _make_hunt()
        page1 = [{"id": i} for i in range(100)]

        svc.get.return_value = FakeResponse(200, page1)

        result = hunt._paginate("/orgs/test-org/members", max_items=50)

        assert len(result) == 50

    def test_empty_page_stops(self):
        hunt, svc = _make_hunt()
        svc.get.return_value = FakeResponse(200, [])

        result = hunt._paginate("/path", max_items=100)

        assert result == []
        svc.get.assert_called_once()

    def test_non_list_response_stops(self):
        hunt, svc = _make_hunt()
        svc.get.return_value = FakeResponse(200, {"not": "a list"})

        result = hunt._paginate("/path", max_items=100)

        assert result == []

    def test_http_error_raises_runtime_error(self):
        hunt, svc = _make_hunt()
        svc.get.return_value = FakeResponse(404, {"message": "Not Found"})

        with pytest.raises(RuntimeError, match="404"):
            hunt._paginate("/bad/path", max_items=100)

    def test_params_passed_to_get(self):
        hunt, svc = _make_hunt()
        svc.get.return_value = FakeResponse(200, [{"id": 1}])

        hunt._paginate("/path", params={"state": "open"}, max_items=100)

        called_params = svc.get.call_args[1]["params"]
        assert called_params["state"] == "open"
        assert called_params["per_page"] == 100
        assert called_params["page"] == 1


# ---- hunt_secret_scanning_alerts ----

class TestHuntSecretScanningAlerts:
    def test_org_level_endpoint(self):
        hunt, svc = _make_hunt()
        svc.get.return_value = FakeResponse(200, [{"number": 1, "state": "open"}])

        result = hunt.hunt_secret_scanning_alerts(state="open")

        assert result.success is True
        assert len(result.details["alerts"]) == 1
        called_path = svc.get.call_args[0][0]
        assert called_path == "/orgs/test-org/secret-scanning/alerts"

    def test_repo_level_endpoint(self):
        hunt, svc = _make_hunt()
        svc.get.return_value = FakeResponse(200, [{"number": 2}])

        result = hunt.hunt_secret_scanning_alerts("my-repo", state="open")

        assert result.success is True
        called_path = svc.get.call_args[0][0]
        assert called_path == "/repos/test-org/my-repo/secret-scanning/alerts"

    def test_state_param_passed(self):
        hunt, svc = _make_hunt()
        svc.get.return_value = FakeResponse(200, [])

        hunt.hunt_secret_scanning_alerts(state="resolved")

        params = svc.get.call_args[1]["params"]
        assert params["state"] == "resolved"

    def test_max_alerts_respected(self):
        hunt, svc = _make_hunt()
        alerts = [{"number": i} for i in range(100)]
        svc.get.return_value = FakeResponse(200, alerts)

        result = hunt.hunt_secret_scanning_alerts(max_alerts=10)

        assert len(result.details["alerts"]) == 10

    def test_api_error_recorded(self):
        hunt, svc = _make_hunt()
        svc.get.return_value = FakeResponse(403, {"message": "GHAS not enabled"})

        result = hunt.hunt_secret_scanning_alerts()

        assert result.success is False
        assert result.errors

    def test_network_error_recorded(self):
        hunt, svc = _make_hunt()
        svc.get.side_effect = requests.exceptions.ConnectionError("timeout")

        result = hunt.hunt_secret_scanning_alerts()

        assert result.success is False
        assert result.errors

    def test_enterprise_config_records_error(self):
        hunt = _enterprise_hunt()
        result = hunt.hunt_secret_scanning_alerts()
        assert result.success is False
        assert result.errors


# ---- hunt_code_scanning_alerts ----

class TestHuntCodeScanningAlerts:
    def test_correct_endpoint(self):
        hunt, svc = _make_hunt()
        svc.get.return_value = FakeResponse(200, [{"number": 1}])

        result = hunt.hunt_code_scanning_alerts("my-repo")

        assert result.success is True
        called_path = svc.get.call_args[0][0]
        assert called_path == "/repos/test-org/my-repo/code-scanning/alerts"

    def test_state_param_passed(self):
        hunt, svc = _make_hunt()
        svc.get.return_value = FakeResponse(200, [])

        hunt.hunt_code_scanning_alerts("repo", state="dismissed")

        params = svc.get.call_args[1]["params"]
        assert params["state"] == "dismissed"

    def test_alerts_collected(self):
        hunt, svc = _make_hunt()
        svc.get.return_value = FakeResponse(200, [{"number": 1}, {"number": 2}])

        result = hunt.hunt_code_scanning_alerts("repo")

        assert len(result.details["alerts"]) == 2
        assert result.details["statistics"]["repo"] == "repo"

    def test_api_error_recorded(self):
        hunt, svc = _make_hunt()
        svc.get.return_value = FakeResponse(404, {"message": "not found"})

        result = hunt.hunt_code_scanning_alerts("repo")

        assert result.success is False

    def test_enterprise_config_records_error(self):
        hunt = _enterprise_hunt()
        result = hunt.hunt_code_scanning_alerts("repo")
        assert result.success is False
        assert result.errors


# ---- list_org_members ----

class TestListOrgMembers:
    def test_correct_endpoint(self):
        hunt, svc = _make_hunt()
        svc.get.return_value = FakeResponse(200, [{"login": "alice"}])

        result = hunt.list_org_members()

        assert result.success is True
        called_path = svc.get.call_args[0][0]
        assert called_path == "/orgs/test-org/members"

    def test_role_param_passed_when_set(self):
        hunt, svc = _make_hunt()
        svc.get.return_value = FakeResponse(200, [])

        hunt.list_org_members(role="admin")

        params = svc.get.call_args[1]["params"]
        assert params["role"] == "admin"

    def test_no_role_param_when_unset(self):
        hunt, svc = _make_hunt()
        svc.get.return_value = FakeResponse(200, [])

        hunt.list_org_members()

        params = svc.get.call_args[1]["params"]
        assert "role" not in params

    def test_members_collected(self):
        hunt, svc = _make_hunt()
        svc.get.return_value = FakeResponse(200, [{"login": "alice"}, {"login": "bob"}])

        result = hunt.list_org_members()

        assert len(result.details["members"]) == 2

    def test_max_members_respected(self):
        hunt, svc = _make_hunt()
        members = [{"login": f"u{i}"} for i in range(100)]
        svc.get.return_value = FakeResponse(200, members)

        result = hunt.list_org_members(max_members=5)

        assert len(result.details["members"]) == 5

    def test_api_error_recorded(self):
        hunt, svc = _make_hunt()
        svc.get.return_value = FakeResponse(403, {"message": "forbidden"})

        result = hunt.list_org_members()

        assert result.success is False

    def test_enterprise_config_records_error(self):
        hunt = _enterprise_hunt()
        result = hunt.list_org_members()
        assert result.success is False
        assert result.errors


# ---- list_outside_collaborators ----

class TestListOutsideCollaborators:
    def test_correct_endpoint(self):
        hunt, svc = _make_hunt()
        svc.get.return_value = FakeResponse(200, [{"login": "ext-user"}])

        result = hunt.list_outside_collaborators()

        assert result.success is True
        called_path = svc.get.call_args[0][0]
        assert called_path == "/orgs/test-org/outside_collaborators"

    def test_collaborators_collected(self):
        hunt, svc = _make_hunt()
        svc.get.return_value = FakeResponse(200, [{"login": "ext1"}, {"login": "ext2"}])

        result = hunt.list_outside_collaborators()

        assert len(result.details["collaborators"]) == 2
        assert result.details["statistics"]["total"] == 2

    def test_api_error_recorded(self):
        hunt, svc = _make_hunt()
        svc.get.return_value = FakeResponse(404, {"message": "not found"})

        result = hunt.list_outside_collaborators()

        assert result.success is False

    def test_enterprise_config_records_error(self):
        hunt = _enterprise_hunt()
        result = hunt.list_outside_collaborators()
        assert result.success is False
        assert result.errors


# ---- list_deploy_keys ----

class TestListDeployKeys:
    def test_correct_endpoint(self):
        hunt, svc = _make_hunt()
        svc.get.return_value = FakeResponse(200, [{"id": 1, "title": "CI key"}])

        result = hunt.list_deploy_keys("my-repo")

        assert result.success is True
        called_path = svc.get.call_args[0][0]
        assert called_path == "/repos/test-org/my-repo/keys"

    def test_keys_collected(self):
        hunt, svc = _make_hunt()
        svc.get.return_value = FakeResponse(200, [{"id": 1}, {"id": 2}])

        result = hunt.list_deploy_keys("repo")

        assert len(result.details["keys"]) == 2
        assert result.details["statistics"]["repo"] == "repo"

    def test_max_keys_respected(self):
        hunt, svc = _make_hunt()
        keys = [{"id": i} for i in range(100)]
        svc.get.return_value = FakeResponse(200, keys)

        result = hunt.list_deploy_keys("repo", max_keys=3)

        assert len(result.details["keys"]) == 3

    def test_api_error_recorded(self):
        hunt, svc = _make_hunt()
        svc.get.return_value = FakeResponse(404, {"message": "not found"})

        result = hunt.list_deploy_keys("repo")

        assert result.success is False

    def test_network_error_recorded(self):
        hunt, svc = _make_hunt()
        svc.get.side_effect = requests.exceptions.Timeout("timed out")

        result = hunt.list_deploy_keys("repo")

        assert result.success is False
        assert result.errors

    def test_enterprise_config_records_error(self):
        hunt = _enterprise_hunt()
        result = hunt.list_deploy_keys("repo")
        assert result.success is False
        assert result.errors
