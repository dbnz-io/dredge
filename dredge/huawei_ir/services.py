"""Lazy SDK adapters. Only this boundary knows Huawei SDK model classes."""
from __future__ import annotations

from importlib import import_module
import re

from .auth import HuaweiCredentialFactory


class HuaweiServiceError(RuntimeError):
    def __init__(self, message, *, status=None, code=None):
        super().__init__(message)
        self.status = status if isinstance(status, int) else None
        self.code = code if isinstance(code, str) and re.fullmatch(r"[\w.-]{1,80}", code) else None


_SERVICES = {
    "functiongraph": ("v2", "FunctionGraph"),
    "ecs": ("v2", "Ecs"),
    "cae": ("v1", "Cae"),
    "lts": ("v2", "Lts"),
    "csms": ("v1", "Csms"),
    "vpc": ("v3", "Vpc"),
    "vpc_flow": ("v2", "Vpc"),
    "rds": ("v3", "Rds"),
    "evs": ("v2", "Evs"),
    "cce": ("v3", "Cce"),
    "cts": ("v3", "Cts"),
    "hss": ("v5", "Hss"),
    "secmaster": ("v1", "SecMaster"),
}


def _plain(value):
    """SDK to_dict leaves models nested inside dict-of-lists (ECS addresses)."""
    if isinstance(value, dict):
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    if hasattr(value, "to_dict"):
        return _plain(value.to_dict())
    return value


class HuaweiServiceRegistry:
    def __init__(self, config):
        self.config = config
        self.auth = HuaweiCredentialFactory(config)
        self._clients = {}
        self._obs = None
        self._refresh_client = None
        self._iam = None
        self._regional_obs = {}

    def iam_call(self, operation, **params):
        from .profiles import IamDiscovery
        if self._iam is None:
            self._iam = IamDiscovery(lambda: self.auth.get_credentials(require_project=False), self.config.timeout)
        return self._iam.call(operation, **params)

    def obs_for_region(self, region):
        from .config import HuaweiAuthConfig
        if region == self.config.region_name:
            return self
        if region not in self._regional_obs:
            self._regional_obs[region] = HuaweiServiceRegistry(HuaweiAuthConfig(
                region_name=region, project_id=self.config.project_id,
                credential_provider=lambda: self.auth.get_credentials(require_project=False), timeout=self.config.timeout))
        return self._regional_obs[region]

    def _http_config(self):
        from huaweicloudsdkcore.http.http_config import HttpConfig
        config = HttpConfig.get_default_config()
        config.timeout = (self.config.timeout, self.config.timeout)
        config.retry_times = 0
        config.ignore_ssl_verification = False
        return config

    def call(self, service, operation, **params):
        """Construct typed requests, returning SDK snake_case dictionaries."""
        credentials = self.auth.get_credentials()
        try:
            version, prefix = _SERVICES[service]
            sdk_service = "vpc" if service == "vpc_flow" else service
            module = import_module(f"huaweicloudsdk{sdk_service}.{version}")
            if service not in self._clients:
                region_module = import_module(f"huaweicloudsdk{sdk_service}.{version}.region.{sdk_service}_region")
                region = getattr(region_module, prefix + "Region").value_of(self.config.region_name)
                self._clients[service] = (getattr(module, prefix + "Client").new_builder()
                                         .with_credentials(credentials).with_region(region)
                                         .with_http_config(self._http_config()).build())
            client = self._clients[service]
            client.with_credentials(credentials)
            if service == "lts" and isinstance(params.get("body"), dict):
                params["body"] = module.QueryLtsLogParams(**params["body"])
            request_class = "".join(part.capitalize() for part in operation.split("_")) + "Request"
            response = getattr(client, operation)(getattr(module, request_class)(**params))
            return _plain(response.to_dict())
        except ImportError:
            raise HuaweiServiceError('Install Huawei support with pip install "dredge-ir[huawei]"') from None
        except Exception as exc:
            # No response/request bodies: they may contain the secrets under assessment.
            status = getattr(exc, "status_code", None)
            status = str(status) if isinstance(status, int) else "unavailable"
            raise HuaweiServiceError(f"{service}.{operation} failed (HTTP {status})",
                                     status=getattr(exc, "status_code", None), code=getattr(exc, "error_code", None)) from None

    def obs_call(self, operation, **params):
        credentials = self.auth.get_credentials(require_project=False)
        try:
            from obs import ObsClient, GetObjectHeader
            from huaweicloudsdkcore.client import Client
            # Use the SDK refresh mechanism for federated/metadata credentials
            # before transferring the current AK/SK/token to the separate OBS SDK.
            if self._refresh_client is None:
                self._refresh_client = Client().with_config(self._http_config())
                self._refresh_client.init_http_client()
            credentials.process_sts(self._refresh_client.get_http_client())
            if not credentials.ak or not credentials.sk:
                raise HuaweiServiceError("Huawei credentials contain no AK/SK after refresh")
            if self._obs is None:
                self._obs = ObsClient(
                    access_key_id=credentials.ak, secret_access_key=credentials.sk,
                    security_token=credentials.security_token,
                    server=f"https://obs.{self.config.region_name}.myhuaweicloud.com",
                    region=self.config.region_name, ssl_verify=True,
                    max_retry_count=0, max_redirect_count=0, timeout=self.config.timeout,
                )
            self._obs.refresh(credentials.ak, credentials.sk, credentials.security_token)
            if isinstance(params.get("headers"), dict):
                params["headers"] = GetObjectHeader(**params["headers"])
            response = getattr(self._obs, operation)(**params)
            if not isinstance(response.status, int) or not 200 <= response.status < 300:
                status = response.status if isinstance(response.status, int) else "unavailable"
                raise HuaweiServiceError(f"obs.{operation} failed (HTTP {status})",
                                         status=response.status, code=getattr(response, "errorCode", None))
            return response
        except HuaweiServiceError:
            raise
        except ImportError:
            raise HuaweiServiceError('Install Huawei support with pip install "dredge-ir[huawei]"') from None
        except Exception:
            raise HuaweiServiceError(f"obs.{operation} failed") from None

    def close(self):
        for registry in self._regional_obs.values():
            registry.close()
        if self._obs is not None:
            self._obs.close()
