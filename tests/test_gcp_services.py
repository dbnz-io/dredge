from unittest.mock import MagicMock, patch

from dredge.gcp_ir import GcpIRNamespace
from dredge.gcp_ir.config import GcpIRConfig
from dredge.gcp_ir.hunt import GcpIRHunt
from dredge.gcp_ir.services import GcpLoggingService


class TestGcpLoggingServiceInit:
    def test_credentials_file_branch(self):
        with (
            patch("dredge.gcp_ir.services.service_account.Credentials.from_service_account_file") as mock_creds,
            patch("dredge.gcp_ir.services.logging.Client") as mock_client,
        ):
            mock_creds.return_value = "fake-creds"
            cfg = GcpIRConfig(project_id="my-project", credentials_file="/path/to/creds.json")

            GcpLoggingService(cfg)

            mock_creds.assert_called_once_with("/path/to/creds.json")
            mock_client.assert_called_once_with(project="my-project", credentials="fake-creds")

    def test_adc_branch_no_credentials_file(self):
        with patch("dredge.gcp_ir.services.logging.Client") as mock_client:
            cfg = GcpIRConfig(project_id="my-project")

            GcpLoggingService(cfg)

            mock_client.assert_called_once_with(project="my-project")


class TestGcpLoggingServiceProperties:
    def test_project_id_property(self):
        with patch("dredge.gcp_ir.services.logging.Client"):
            cfg = GcpIRConfig(project_id="my-project")
            svc = GcpLoggingService(cfg)
            assert svc.project_id == "my-project"

    def test_client_property_returns_constructed_client(self):
        with patch("dredge.gcp_ir.services.logging.Client") as mock_client:
            mock_instance = MagicMock()
            mock_client.return_value = mock_instance
            cfg = GcpIRConfig(project_id="my-project")
            svc = GcpLoggingService(cfg)
            assert svc.client is mock_instance


class TestGcpLoggingServiceListEntries:
    def test_list_entries_calls_client_with_expected_kwargs(self):
        with patch("dredge.gcp_ir.services.logging.Client") as mock_client:
            mock_instance = MagicMock()
            mock_client.return_value = mock_instance
            cfg = GcpIRConfig(project_id="my-project")
            svc = GcpLoggingService(cfg)

            svc.list_entries(filter_='resource.type="gce_instance"', page_size=50, order_by="timestamp desc")

            mock_instance.list_entries.assert_called_once_with(
                filter_='resource.type="gce_instance"',
                page_size=50,
                page_token=None,
                order_by="timestamp desc",
            )

    def test_list_entries_passes_page_token(self):
        with patch("dredge.gcp_ir.services.logging.Client") as mock_client:
            mock_instance = MagicMock()
            mock_client.return_value = mock_instance
            cfg = GcpIRConfig(project_id="my-project")
            svc = GcpLoggingService(cfg)

            svc.list_entries(filter_="x", page_size=10, order_by="timestamp asc", page_token="tok-123")

            mock_instance.list_entries.assert_called_once_with(
                filter_="x",
                page_size=10,
                page_token="tok-123",
                order_by="timestamp asc",
            )


class TestGcpIRNamespace:
    def test_wires_hunt_with_logging_service(self):
        with patch("dredge.gcp_ir.services.logging.Client"):
            cfg = GcpIRConfig(project_id="my-project")
            ns = GcpIRNamespace(cfg)

            assert isinstance(ns.hunt, GcpIRHunt)
