import os
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch
import pytest
from dredge.auth import AwsAuthConfig, AwsSessionFactory


class TestAwsSessionFactoryBaseSession:
    def test_explicit_keys_used(self):
        cfg = AwsAuthConfig(
            access_key_id="AKID",
            secret_access_key="SECRET",
            session_token="TOKEN",
            region_name="us-east-1",
        )
        factory = AwsSessionFactory(cfg)

        with patch("dredge.auth.boto3.Session") as mock_cls:
            factory.get_session()

        mock_cls.assert_called_once_with(
            aws_access_key_id="AKID",
            aws_secret_access_key="SECRET",
            aws_session_token="TOKEN",
            region_name="us-east-1",
        )

    def test_profile_used_when_no_explicit_keys(self):
        cfg = AwsAuthConfig(profile_name="my-profile", region_name="eu-west-1")
        factory = AwsSessionFactory(cfg)

        with patch("dredge.auth.boto3.Session") as mock_cls:
            factory.get_session()

        mock_cls.assert_called_once_with(
            profile_name="my-profile",
            region_name="eu-west-1",
        )

    def test_default_chain_when_no_keys_no_profile(self):
        cfg = AwsAuthConfig(region_name="ap-southeast-1")
        factory = AwsSessionFactory(cfg)

        with patch("dredge.auth.boto3.Session") as mock_cls:
            factory.get_session()

        mock_cls.assert_called_once_with(region_name="ap-southeast-1")

    def test_session_is_cached_after_first_call(self):
        cfg = AwsAuthConfig()
        factory = AwsSessionFactory(cfg)

        with patch("dredge.auth.boto3.Session") as mock_cls:
            s1 = factory.get_session()
            s2 = factory.get_session()

        assert s1 is s2
        mock_cls.assert_called_once()


class TestAwsSessionFactoryRoleAssumption:
    def _make_sts(self, key="TMP_KEY", secret="TMP_SECRET", token="TMP_TOKEN"):
        sts = MagicMock()
        sts.assume_role.return_value = {
            "Credentials": {
                "AccessKeyId": key,
                "SecretAccessKey": secret,
                "SessionToken": token,
            }
        }
        return sts

    def test_assumes_role_when_role_arn_provided(self):
        cfg = AwsAuthConfig(role_arn="arn:aws:iam::123:role/MyRole")
        factory = AwsSessionFactory(cfg)

        mock_base = MagicMock()
        mock_sts = self._make_sts()
        mock_base.client.return_value = mock_sts

        with patch("dredge.auth.boto3.Session", return_value=mock_base):
            factory.get_session()

        mock_sts.assume_role.assert_called_once()
        kwargs = mock_sts.assume_role.call_args[1]
        assert kwargs["RoleArn"] == "arn:aws:iam::123:role/MyRole"
        assert kwargs["RoleSessionName"] == "dredge-session"

    def test_external_id_included_when_set(self):
        cfg = AwsAuthConfig(role_arn="arn:aws:iam::123:role/R", external_id="ext-123")
        factory = AwsSessionFactory(cfg)

        mock_base = MagicMock()
        mock_sts = self._make_sts()
        mock_base.client.return_value = mock_sts

        with patch("dredge.auth.boto3.Session", return_value=mock_base):
            factory.get_session()

        kwargs = mock_sts.assume_role.call_args[1]
        assert kwargs["ExternalId"] == "ext-123"

    def test_mfa_serial_without_provider_raises(self):
        cfg = AwsAuthConfig(
            role_arn="arn:aws:iam::123:role/R",
            mfa_serial="arn:aws:iam::123:mfa/device",
        )
        factory = AwsSessionFactory(cfg)

        with patch("dredge.auth.boto3.Session", return_value=MagicMock()):
            with pytest.raises(ValueError, match="mfa_token_provider"):
                factory.get_session()

    def test_mfa_with_provider_includes_token(self):
        token_provider = MagicMock(return_value="654321")
        cfg = AwsAuthConfig(
            role_arn="arn:aws:iam::123:role/R",
            mfa_serial="arn:aws:iam::123:mfa/device",
            mfa_token_provider=token_provider,
        )
        factory = AwsSessionFactory(cfg)

        mock_base = MagicMock()
        mock_sts = self._make_sts()
        mock_base.client.return_value = mock_sts

        with patch("dredge.auth.boto3.Session", return_value=mock_base):
            factory.get_session()

        kwargs = mock_sts.assume_role.call_args[1]
        assert kwargs["SerialNumber"] == "arn:aws:iam::123:mfa/device"
        assert kwargs["TokenCode"] == "654321"

    def _make_sts_with_expiry(self, expiry):
        sts = MagicMock()
        sts.assume_role.return_value = {
            "Credentials": {
                "AccessKeyId": "TMP_KEY",
                "SecretAccessKey": "TMP_SECRET",
                "SessionToken": "TMP_TOKEN",
                "Expiration": expiry,
            }
        }
        return sts

    def test_expired_session_is_rebuilt(self):
        cfg = AwsAuthConfig(role_arn="arn:aws:iam::123:role/R")
        factory = AwsSessionFactory(cfg)

        past = datetime(2020, 1, 1, tzinfo=timezone.utc)
        mock_base = MagicMock()
        mock_sts = self._make_sts_with_expiry(past)
        mock_base.client.return_value = mock_sts

        with patch("dredge.auth.boto3.Session", return_value=mock_base):
            factory.get_session()
            factory.get_session()  # expiry is in the past — must rebuild

        assert mock_sts.assume_role.call_count == 2

    def test_unexpired_session_is_cached(self):
        cfg = AwsAuthConfig(role_arn="arn:aws:iam::123:role/R")
        factory = AwsSessionFactory(cfg)

        future = datetime(2099, 1, 1, tzinfo=timezone.utc)
        mock_base = MagicMock()
        mock_sts = self._make_sts_with_expiry(future)
        mock_base.client.return_value = mock_sts

        with patch("dredge.auth.boto3.Session", return_value=mock_base):
            factory.get_session()
            factory.get_session()  # still valid — should reuse

        assert mock_sts.assume_role.call_count == 1

    def test_assumed_role_session_built_with_temp_creds(self):
        cfg = AwsAuthConfig(role_arn="arn:aws:iam::123:role/R")
        factory = AwsSessionFactory(cfg)

        mock_base = MagicMock()
        mock_sts = self._make_sts()
        mock_base.client.return_value = mock_sts

        sessions_created = []

        def track_sessions(**kwargs):
            s = MagicMock()
            s.client.return_value = mock_sts  # each returned session has the sts client
            sessions_created.append(kwargs)
            return s

        with patch("dredge.auth.boto3.Session", side_effect=track_sessions):
            factory.get_session()

        # Second call builds the assumed-role session with temp creds
        assert sessions_created[1]["aws_access_key_id"] == "TMP_KEY"
        assert sessions_created[1]["aws_secret_access_key"] == "TMP_SECRET"
        assert sessions_created[1]["aws_session_token"] == "TMP_TOKEN"
