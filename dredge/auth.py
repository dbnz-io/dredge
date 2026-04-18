from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable, Optional

import boto3


MfaTokenProvider = Callable[[], str]


@dataclass
class AwsAuthConfig:
    """
    Defines how Dredge should authenticate to AWS.

    Precedence (if multiple fields are set):
      1) Explicit access keys
      2) Profile name
      3) Default environment / instance role

    After base credentials are resolved, an optional `role_arn` can be assumed.
    """
    # Explicit credentials
    access_key_id: Optional[str] = None
    secret_access_key: Optional[str] = None
    session_token: Optional[str] = None

    # Profile-based auth
    profile_name: Optional[str] = None

    # Optional role to assume on top of the base auth
    role_arn: Optional[str] = None
    external_id: Optional[str] = None
    session_name: str = "dredge-session"

    # Region
    region_name: Optional[str] = None

    # (Optional) MFA
    mfa_serial: Optional[str] = None
    mfa_token_provider: Optional[MfaTokenProvider] = None

    # Session duration for assumed roles (seconds; AWS default 3600)
    role_session_duration: int = 3600


class AwsSessionFactory:
    """
    Responsible for building a boto3.Session according to AwsAuthConfig.

    - If explicit keys are provided: use them.
    - Else if profile_name is provided: use that profile.
    - Else: rely on default credential chain on the server.

    If role_arn is provided, we assume that role on top of the base credentials.
    """

    def __init__(self, config: AwsAuthConfig) -> None:
        self._config = config
        self._cached_session: Optional[boto3.Session] = None
        # Set only for assumed-role sessions; None means no expiry is tracked.
        self._session_expiry: Optional[datetime] = None

    def get_session(self) -> boto3.Session:
        if self._cached_session is None or self._is_expiring_soon():
            self._cached_session = self._build_session()
        return self._cached_session

    def _is_expiring_soon(self) -> bool:
        """Return True if the cached session expires within 5 minutes."""
        if self._session_expiry is None:
            return False
        return datetime.now(timezone.utc) >= self._session_expiry - timedelta(minutes=5)

    # ------------ internal helpers ------------

    def _build_session(self) -> boto3.Session:
        base_session = self._build_base_session()

        if not self._config.role_arn:
            return base_session

        return self._assume_role_session(base_session)

    def _build_base_session(self) -> boto3.Session:
        cfg = self._config

        # 1) Explicit credentials
        if cfg.access_key_id and cfg.secret_access_key:
            return boto3.Session(
                aws_access_key_id=cfg.access_key_id,
                aws_secret_access_key=cfg.secret_access_key,
                aws_session_token=cfg.session_token,
                region_name=cfg.region_name,
            )

        # 2) Profile-based
        if cfg.profile_name:
            return boto3.Session(
                profile_name=cfg.profile_name,
                region_name=cfg.region_name,
            )

        # 3) Default chain on the server
        return boto3.Session(region_name=cfg.region_name)

    def _assume_role_session(self, base_session: boto3.Session) -> boto3.Session:
        cfg = self._config
        sts = base_session.client("sts")

        assume_args = {
            "RoleArn": cfg.role_arn,
            "RoleSessionName": cfg.session_name,
            "DurationSeconds": cfg.role_session_duration,
        }

        if cfg.external_id:
            assume_args["ExternalId"] = cfg.external_id

        if cfg.mfa_serial:
            if not cfg.mfa_token_provider:
                raise ValueError("mfa_serial is set but mfa_token_provider is None")

            assume_args["SerialNumber"] = cfg.mfa_serial
            assume_args["TokenCode"] = cfg.mfa_token_provider()

        resp = sts.assume_role(**assume_args)
        creds = resp["Credentials"]

        # Track expiry so get_session() can refresh before credentials expire.
        # AWS always returns Expiration for AssumeRole; use .get() for test safety.
        self._session_expiry = creds.get("Expiration")

        return boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
            region_name=cfg.region_name,
        )
