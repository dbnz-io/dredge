from __future__ import annotations

from .config import HuaweiAuthConfig


class HuaweiAuthError(ValueError):
    """A sanitized authentication error; never includes a credential value."""


class HuaweiCredentialFactory:
    def __init__(self, config: HuaweiAuthConfig):
        self.config = config
        self._credentials = None

    def get_credentials(self, *, require_project=True):
        try:
            from huaweicloudsdkcore.auth.credentials import BasicCredentials
            from huaweicloudsdkcore.auth.provider import CredentialProviderChain, ProfileCredentialProvider
        except ImportError:
            raise HuaweiAuthError('Install Huawei support with pip install "dredge-ir[huawei]"') from None
        cfg = self.config
        try:
            if cfg.credential_provider:
                # Called for every service request, including OBS requests.
                credentials = cfg.credential_provider()
            elif self._credentials is not None:
                credentials = self._credentials
            elif cfg.access_key_id:
                credentials = BasicCredentials(cfg.access_key_id, cfg.secret_access_key, cfg.project_id)
                credentials.with_security_token(cfg.security_token)
            elif cfg.profile_name:
                section = "basic" if cfg.profile_name == "basic" else "basic." + cfg.profile_name
                credentials = ProfileCredentialProvider(section).get_credentials()
            else:
                credentials = CredentialProviderChain.get_basic().get_credentials()
            if not isinstance(credentials, BasicCredentials):
                raise HuaweiAuthError("Huawei credential_provider must return SDK BasicCredentials")
            if require_project and cfg.project_id:
                credentials.with_project_id(cfg.project_id)
            if require_project and not credentials.project_id:
                raise HuaweiAuthError("Set Huawei project_id in the config, environment, or credential profile")
            self._credentials = credentials
            return credentials
        except HuaweiAuthError:
            raise
        except Exception:
            # SDK/provider exception messages may contain credentials or server bodies.
            raise HuaweiAuthError("Unable to resolve Huawei credentials; check the configured credential source") from None
