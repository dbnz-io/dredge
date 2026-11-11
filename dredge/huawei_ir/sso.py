"""Huawei Identity Center device authorization and temporary agency credentials.

Uses the official OIDC/Portal SDKs. KooCLI profile metadata can be imported,
but its encrypted token store is not read or modified.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import threading
import time
from urllib.parse import urlsplit

from .auth import HuaweiAuthError

_DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"
# OAuth authentication-method name required by Huawei, not a credential.
_TOKEN_AUTH_METHOD = "client_secret_post"  # nosec B105


class SsoApiError(HuaweiAuthError):
    def __init__(self, operation, code=None, status=None):
        self.code = code if isinstance(code, str) and re.fullmatch(r"[\w.-]{1,80}", code) else "unknown"
        self.status = status if isinstance(status, int) else None
        super().__init__(f"{operation} failed ({self.code}, HTTP {self.status or 'unavailable'})")


def _sdk_call(client, operation, request):
    try:
        # SDK model.to_dict() masks access/refresh tokens and agency keys. The
        # documented response accessor preserves the actual wire payload. Keep
        # it inside the authentication/discovery boundary, never in reports.
        value = getattr(client, operation)(request).to_json_object()
        if not isinstance(value, dict):
            raise HuaweiAuthError("Identity API returned an invalid response")
        return value
    except Exception as exc:
        raise SsoApiError(operation, getattr(exc, "error_code", None), getattr(exc, "status_code", None)) from None


class IdentityCenterApi:
    def __init__(self, region, timeout=20):
        try:
            import huaweicloudsdkidentitycenteroidc.v1 as oidc
            import huaweicloudsdkidentitycenterportalapi.v1 as portal
            from huaweicloudsdkidentitycenteroidc.v1.identitycenteroidc_credentials import IdentityCenterOIDCCredentials
            from huaweicloudsdkidentitycenterportalapi.v1.identitycenterportalapi_credentials import IdentityCenterPortalAPICredentials
            from huaweicloudsdkidentitycenteroidc.v1.region.identitycenteroidc_region import IdentityCenterOIDCRegion
            from huaweicloudsdkcore.http.http_config import HttpConfig
        except ImportError:
            raise HuaweiAuthError('Install Huawei support with pip install "dredge-ir[huawei]"') from None
        config = HttpConfig.get_default_config()
        config.timeout, config.retry_times, config.ignore_ssl_verification = (timeout, timeout), 0, False
        self.oidc_models, self.portal_models = oidc, portal
        try:
            self.oidc = (oidc.IdentityCenterOIDCClient.new_builder().with_credentials(IdentityCenterOIDCCredentials())
                         .with_region(IdentityCenterOIDCRegion.value_of(region)).with_http_config(config).build())
            self.portal = (portal.IdentityCenterPortalAPIClient.new_builder().with_credentials(IdentityCenterPortalAPICredentials())
                           # PortalAPI uses the global endpoint shipped in its
                           # SDK; its region catalog only lists two CN aliases.
                           .with_endpoint("https://portal-identitycenter.myhuaweicloud.com")
                           .with_http_config(config).build())
        except Exception:
            raise HuaweiAuthError("Unable to initialize Identity Center clients for the configured SSO region") from None

    def oidc_call(self, operation, **body):
        stem = "".join(part.capitalize() for part in operation.split("_"))
        model = getattr(self.oidc_models, stem + "ReqBody")(**body)
        return _sdk_call(self.oidc, operation, getattr(self.oidc_models, stem + "Request")(body=model))

    def portal_call(self, operation, access_token, **kwargs):
        stem = "".join(part.capitalize() for part in operation.split("_"))
        return _sdk_call(self.portal, operation, getattr(self.portal_models, stem + "Request")(
            access_token=access_token, **kwargs))


def _epoch(value):
    value = float(value)
    return value / 1000 if value > 100_000_000_000 else value


class TokenCache:
    def __init__(self, key, directory=None):
        self.directory = Path(directory or os.getenv("DREDGE_HUAWEI_SSO_CACHE_DIR")
                              or Path.home() / ".huaweicloud" / "dredge-sso-cache")
        self.path = self.directory / (hashlib.sha256(key.encode()).hexdigest() + ".json")

    def _prepare(self):
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = self.directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or (hasattr(os, "getuid") and info.st_uid != os.getuid()):
            raise HuaweiAuthError("SSO cache must be an owned directory, not a symlink")
        os.chmod(self.directory, 0o700)

    def read(self):
        try:
            self._prepare()
            fd = os.open(self.path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            with os.fdopen(fd) as fh:
                info = os.fstat(fh.fileno())
                if (not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077
                        or (hasattr(os, "getuid") and info.st_uid != os.getuid())):
                    raise HuaweiAuthError("SSO cache file must be owned by the current user with mode 0600")
                value = json.load(fh)
                return value if isinstance(value, dict) else {}
        except FileNotFoundError:
            return {}
        except (OSError, ValueError):
            raise HuaweiAuthError("Unable to read SSO cache securely") from None

    def write(self, value):
        temporary = None
        try:
            self._prepare()
            fd, temporary = tempfile.mkstemp(prefix=".token-", dir=self.directory)
            with os.fdopen(fd, "w") as fh:
                os.fchmod(fh.fileno(), 0o600)
                json.dump(value, fh)
            os.replace(temporary, self.path)
        except OSError:
            raise HuaweiAuthError("Unable to write SSO cache securely") from None
        finally:
            if temporary and os.path.exists(temporary):
                os.unlink(temporary)


def _https_url(value):
    try:
        url = urlsplit(value)
        return url.scheme == "https" and bool(url.hostname) and not url.username and not url.password
    except (TypeError, ValueError):
        return False


class SsoSession:
    def __init__(self, profile, *, timeout=20, cache_dir=None, notify=None):
        if not _https_url(profile.get("sso_start_url")):
            raise HuaweiAuthError("SSO profile requires an HTTPS sso_start_url")
        self.start_url = profile["sso_start_url"].rstrip("/")
        self.api = IdentityCenterApi(profile["sso_region"], timeout)
        key = json.dumps([profile["sso_region"], self.start_url, profile["session_name"]])
        self.cache = TokenCache(key, cache_dir)
        self.data = self.cache.read()
        self.notify = notify or (lambda message: print(message, file=sys.stderr))
        self.lock = threading.RLock()
        self.login_attempted = False

    def _save_token(self, response):
        info = response.get("token_info") or {}
        if not info.get("access_token") or not isinstance(info.get("expires_in"), (int, float)):
            raise HuaweiAuthError("Identity Center returned an incomplete access token")
        # expires_in is documented as seconds, although older API examples use
        # an epoch. Support both without treating an epoch as a multi-year TTL.
        expiry = info["expires_in"]
        self.data.update(access_token=info["access_token"],
                         expires_at=_epoch(expiry) if expiry > 100_000_000 else time.time() + expiry)
        if info.get("refresh_token"):
            self.data["refresh_token"] = info["refresh_token"]
        self.cache.write(self.data)

    def token(self, *, allow_login=False, force_refresh=False):
        with self.lock:
            if not force_refresh and self.data.get("access_token") and self.data.get("expires_at", 0) > time.time() + 60:
                return self.data["access_token"]
            client = self.data.get("client") or {}
            if self.data.get("refresh_token") and client.get("client_secret_expires_at", 0) > time.time() + 60:
                try:
                    self._save_token(self.api.oidc_call("create_token", client_id=client["client_id"],
                        client_secret=client["client_secret"], grant_type="refresh_token",
                        refresh_token=self.data["refresh_token"]))
                    return self.data["access_token"]
                except SsoApiError as exc:
                    if exc.status not in (400, 401, 403, 404):
                        raise
                    self.data.pop("refresh_token", None)
            if not allow_login or self.login_attempted:
                raise HuaweiAuthError("SSO session unavailable; rerun with --sso-login")
            self.login_attempted = True
            # A fresh authorization can belong to a different user. Never retain
            # a previous user's refresh token if this response omits one.
            self.data.pop("refresh_token", None)
            self.data.pop("access_token", None)
            if not client or client.get("client_secret_expires_at", 0) <= time.time() + 60:
                client = self.api.oidc_call("register_client", client_name="dredge-ir", client_type="public",
                    token_endpoint_auth_method=_TOKEN_AUTH_METHOD, scopes=["openid"],
                    grant_types=[_DEVICE_GRANT], response_types=["code"]).get("client_info") or {}
                if not client.get("client_id") or not client.get("client_secret"):
                    raise HuaweiAuthError("Identity Center returned an incomplete client registration")
                client["client_secret_expires_at"] = _epoch(client["client_secret_expires_at"])
                self.data["client"] = client
                self.cache.write(self.data)
            device = self.api.oidc_call("start_device_authorization", client_id=client["client_id"],
                                       client_secret=client["client_secret"], start_url=self.start_url)
            url = device.get("verification_uri")
            if not _https_url(url) or not device.get("device_code") or not device.get("user_code"):
                raise HuaweiAuthError("Identity Center returned incomplete device authorization")
            self.notify(f"Huawei SSO: open {url} and enter code {device['user_code']} to authorize Dredge.")
            deadline = time.monotonic() + min(600, max(1, int(device.get("expires_in") or 600)))
            interval = max(1, int(device.get("interval") or 5))
            while time.monotonic() < deadline:
                time.sleep(min(interval, max(0, deadline - time.monotonic())))
                if time.monotonic() >= deadline:
                    break
                try:
                    self._save_token(self.api.oidc_call("create_token", client_id=client["client_id"],
                        client_secret=client["client_secret"], grant_type=_DEVICE_GRANT, device_code=device["device_code"]))
                    return self.data["access_token"]
                except SsoApiError as exc:
                    if exc.code in ("IIC.1608", "authorization_pending", "AuthorizationPendingException"):
                        continue
                    if exc.code in ("slow_down", "SlowDownException") or exc.status == 429:
                        interval += 5
                        continue
                    raise
            raise HuaweiAuthError("SSO device authorization timed out")

    def call(self, operation, *, allow_login=False, **kwargs):
        with self.lock:
            token = self.token(allow_login=allow_login)
            try:
                return self.api.portal_call(operation, token, **kwargs)
            except SsoApiError as exc:
                if exc.code != "IIC.1604" and exc.status != 401:
                    raise
                token = self.token(allow_login=allow_login, force_refresh=True)
                return self.api.portal_call(operation, token, **kwargs)

    def pages(self, operation, key, **kwargs):
        marker, seen = None, set()
        for _ in range(100):
            page = self.call(operation, limit=100, **kwargs, **({"marker": marker} if marker else {}))
            yield from page.get(key) or []
            marker = (page.get("page_info") or {}).get("next_marker")
            if not marker:
                return
            if marker in seen:
                raise HuaweiAuthError("Identity Center pagination stalled")
            seen.add(marker)
        raise HuaweiAuthError("Identity Center discovery exceeded 100 pages")


class AgencyCredentialProvider:
    def __init__(self, session, account_id, agency_urn):
        self.session, self.account_id, self.agency_urn = session, account_id, agency_urn
        self.value = {}
        self.lock = threading.Lock()

    def __call__(self, project_id=None):
        from huaweicloudsdkcore.auth.credentials import BasicCredentials
        with self.lock:
            if self.value.get("expiration", 0) <= time.time() + 120:
                value = self.session.call("get_agency_credentials", target_account_id=self.account_id,
                                          agency_urn=self.agency_urn).get("agency_credentials") or {}
                if not all(value.get(k) for k in ("access_key_id", "secret_access_key", "session_token", "expiration")):
                    raise HuaweiAuthError("Identity Center returned incomplete agency credentials")
                value["expiration"] = _epoch(value["expiration"])
                if value["expiration"] <= time.time() + 30:
                    raise HuaweiAuthError("Identity Center returned expired agency credentials")
                self.value = value
            return BasicCredentials(self.value["access_key_id"], self.value["secret_access_key"], project_id
                                    ).with_security_token(self.value["session_token"])
