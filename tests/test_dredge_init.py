import os
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

from unittest.mock import MagicMock, patch
import pytest
import boto3

from dredge import Dredge
from dredge.auth import AwsAuthConfig
from dredge.config import DredgeConfig
from dredge.github_ir.config import GitHubIRConfig


def make_session():
    return MagicMock(spec=boto3.Session)


class TestDredgeInit:
    def test_with_explicit_session(self):
        d = Dredge(session=make_session())
        assert d.aws_ir is not None
        assert d.github_ir is None
        assert d.gcp_ir is None

    def test_session_and_auth_both_set_raises(self):
        with pytest.raises(ValueError, match="Provide either"):
            Dredge(session=make_session(), auth=AwsAuthConfig())

    def test_with_github_config_sets_github_ir(self):
        cfg = GitHubIRConfig(org="test-org", token="tok")
        d = Dredge(session=make_session(), github_config=cfg)
        assert d.github_ir is not None

    def test_without_github_config_github_ir_is_none(self):
        d = Dredge(session=make_session())
        assert d.github_ir is None

    def test_custom_config_used(self):
        config = DredgeConfig(dry_run=True, region_name="eu-west-1")
        d = Dredge(session=make_session(), config=config)
        assert d.config.dry_run is True
        assert d.config.region_name == "eu-west-1"

    def test_default_config_created_when_not_provided(self):
        d = Dredge(session=make_session())
        assert d.config is not None
        assert d.config.dry_run is False

    def test_with_auth_object_builds_session(self):
        auth = AwsAuthConfig(region_name="us-west-2")

        with patch("dredge.auth.boto3.Session", return_value=make_session()):
            d = Dredge(auth=auth)

        assert d.aws_ir is not None

    def test_config_region_from_auth(self):
        auth = AwsAuthConfig(region_name="ap-northeast-1")

        with patch("dredge.auth.boto3.Session", return_value=make_session()):
            d = Dredge(auth=auth)

        assert d.config.region_name == "ap-northeast-1"
