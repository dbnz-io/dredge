import os
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

from unittest.mock import MagicMock
import pytest
from dredge.aws_ir.services import AwsServiceRegistry


def make_registry():
    session = MagicMock()
    return AwsServiceRegistry(session), session


class TestAwsServiceRegistry:
    def test_iam_lazy_loaded(self):
        reg, session = make_registry()
        _ = reg.iam
        session.client.assert_called_with("iam")

    def test_iam_cached_on_second_access(self):
        reg, session = make_registry()
        c1 = reg.iam
        c2 = reg.iam
        assert c1 is c2
        session.client.assert_called_once()

    def test_ec2_lazy_loaded(self):
        reg, session = make_registry()
        _ = reg.ec2
        session.client.assert_called_with("ec2")

    def test_ec2_cached(self):
        reg, session = make_registry()
        c1 = reg.ec2
        c2 = reg.ec2
        assert c1 is c2
        session.client.assert_called_once()

    def test_s3control_lazy_loaded(self):
        reg, session = make_registry()
        _ = reg.s3control
        session.client.assert_called_with("s3control")

    def test_s3_lazy_loaded(self):
        reg, session = make_registry()
        _ = reg.s3
        session.client.assert_called_with("s3")

    def test_lambda_lazy_loaded(self):
        reg, session = make_registry()
        _ = reg.lambda_
        session.client.assert_called_with("lambda")

    def test_cloudtrail_lazy_loaded(self):
        reg, session = make_registry()
        _ = reg.cloudtrail
        session.client.assert_called_with("cloudtrail")


_REMAINING_PROPS = [
    ("kms", "kms"),
    ("guardduty", "guardduty"),
    ("logs", "logs"),
    ("tagging", "resourcegroupstaggingapi"),
    ("rds", "rds"),
    ("ecs", "ecs"),
    ("secretsmanager", "secretsmanager"),
    ("events", "events"),
    ("ssm", "ssm"),
    ("securityhub", "securityhub"),
    ("accessanalyzer", "accessanalyzer"),
    ("awsconfig", "config"),
    ("sts", "sts"),
    ("ecr", "ecr"),
]


class TestAwsServiceRegistryRemainingClients:
    @pytest.mark.parametrize("prop_name,boto3_client_name", _REMAINING_PROPS)
    def test_lazy_loaded(self, prop_name, boto3_client_name):
        reg, session = make_registry()
        _ = getattr(reg, prop_name)
        session.client.assert_called_with(boto3_client_name)

    @pytest.mark.parametrize("prop_name,boto3_client_name", _REMAINING_PROPS)
    def test_cached_on_second_access(self, prop_name, boto3_client_name):
        reg, session = make_registry()
        c1 = getattr(reg, prop_name)
        c2 = getattr(reg, prop_name)
        assert c1 is c2
        session.client.assert_called_once()
