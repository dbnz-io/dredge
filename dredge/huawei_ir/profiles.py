"""Non-secret profile metadata and IAM region/project discovery."""
from __future__ import annotations

import configparser
import json
import os
from pathlib import Path
import re
import shutil
# KooCLI is invoked with a fixed argument vector, never through a shell.
import subprocess  # nosec B404

from .auth import HuaweiAuthError
from .sso import _sdk_call

_REGION = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)+")
_FIELDS = ("region", "project_id", "sso_session", "sso_start_url", "sso_region",
           "account_id", "account_name", "agency_urn", "permission_set_name")


def load_profiles(source="sdk"):
    """Return metadata only. Never copy keys or tokens into scan reports."""
    if source == "koocli":
        executable = shutil.which("hcloud")
        if not executable:
            # User-local installs are common (and avoid requiring root). Codex
            # or another parent process may have started before ~/.local/bin
            # was added to PATH, so look there explicitly as a fallback.
            candidate = Path.home() / ".local" / "bin" / "hcloud"
            if candidate.is_file() and os.access(candidate, os.X_OK):
                executable = str(candidate)
        if not executable:
            raise HuaweiAuthError("KooCLI profile import requires hcloud on PATH")
        try:
            # Only a read-only configuration query. Capture all output so even
            # an older CLI's unmasked output cannot reach the terminal/report.
            response = subprocess.run(  # nosec B603
                [executable, "configure", "list", "--cli-output=json"],
                stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=20, check=True)
            # Some KooCLI builds print log-permission diagnostics before the
            # requested JSON on stdout. Parse the JSON document after that
            # preamble; never surface the raw output, which may contain config.
            json_start = response.stdout.find("{")
            if json_start < 0:
                raise ValueError("KooCLI returned no JSON configuration")
            payload = json.loads(response.stdout[json_start:])
            entries = payload.get("profiles") if isinstance(payload, dict) else None
            if not isinstance(entries, list):
                raise ValueError("KooCLI returned an unsupported profile list")
            catalog = {}
            for entry in entries:
                if entry.get("mode") != "SSO":
                    continue
                name = entry["name"]
                params, auth = entry.get("ssoParam") or {}, entry.get("ssoAuth") or {}
                if name in catalog:
                    raise HuaweiAuthError("Duplicate KooCLI SSO profile name")
                catalog[name] = dict(kind="sso", session_name="koocli:" + name,
                    region=entry.get("region"), project_id=entry.get("projectId"),
                    sso_start_url=params.get("startUrl"), sso_region=params.get("ssoRegion"),
                    account_id=auth.get("accountId"), agency_urn=auth.get("agencyUrn"))
            return catalog
        except Exception:
            raise HuaweiAuthError("Unable to read KooCLI SSO profile metadata; check hcloud configure list") from None
    if source != "sdk":
        raise ValueError("profile_source must be sdk or koocli")
    parser = configparser.ConfigParser(interpolation=None)
    path = Path(os.getenv("HUAWEICLOUD_SDK_CREDENTIALS_FILE") or Path.home() / ".huaweicloud" / "credentials")
    try:
        with path.open(encoding="utf-8") as fh:
            parser.read_file(fh)
    except FileNotFoundError:
        return {}
    except (OSError, configparser.Error, UnicodeError):
        raise HuaweiAuthError("Unable to parse Huawei credential profile metadata") from None
    catalog = {}
    for section in parser.sections():
        if section == "basic":
            name, kind = "basic", "basic"
        elif section.startswith("basic."):
            name, kind = section[6:], "basic"
        elif section.startswith("sso."):
            name, kind = section[4:], "sso"
        else:
            continue
        if not name or name == "all" or name in catalog:
            raise HuaweiAuthError("Huawei profile names must be unique, nonempty, and not 'all'")
        profile = {key: parser.get(section, key, fallback=None) for key in _FIELDS}
        profile["kind"] = kind
        session = profile.get("sso_session")
        profile["session_name"] = "sdk:" + (session or name)
        if session:
            reference = "sso-session " + session
            for key in ("sso_start_url", "sso_region"):
                profile[key] = profile.get(key) or parser.get(reference, key, fallback=None)
        catalog[name] = profile
    return catalog


def validate_sso_profile(profile):
    from .sso import _https_url
    if not _https_url(profile.get("sso_start_url")) or not _REGION.fullmatch(profile.get("sso_region") or ""):
        raise HuaweiAuthError("SSO profile requires sso_start_url (HTTPS) and sso_region")
    for fields in (("account_id", "account_name"), ("agency_urn", "permission_set_name")):
        values = [profile.get(field) for field in fields if profile.get(field)]
        if len(values) != 1 or any("*" in value for value in values):
            raise HuaweiAuthError("SSO profile requires one unmasked account selector and one agency/permission-set selector")


class IamDiscovery:
    def __init__(self, credentials, timeout=20):
        try:
            import huaweicloudsdkiam.v3 as iam
            from huaweicloudsdkcore.auth.credentials import GlobalCredentials
            from huaweicloudsdkcore.http.http_config import HttpConfig
        except ImportError:
            raise HuaweiAuthError('Install Huawei support with pip install "dredge-ir[huawei]"') from None
        self.models, self.credentials = iam, credentials
        self.global_credentials = GlobalCredentials
        config = HttpConfig.get_default_config()
        config.timeout, config.retry_times, config.ignore_ssl_verification = (timeout, timeout), 0, False
        # Explicit endpoint avoids the SDK's implicit domain-ID lookup. These
        # identity discovery APIs have no account/project ID in their path.
        self.client = (iam.IamClient.new_builder().with_credentials(GlobalCredentials())
                       .with_endpoint("https://iam.myhuaweicloud.com").with_http_config(config).build())

    def call(self, operation, **kwargs):
        try:
            credentials = self.credentials()
            credentials.process_sts(self.client.get_http_client())
            if not credentials.ak or not credentials.sk:
                raise HuaweiAuthError("Huawei credentials contain no AK/SK after refresh")
            self.client.with_credentials(self.global_credentials(credentials.ak, credentials.sk)
                                         .with_security_token(credentials.security_token))
            request = getattr(self.models, "".join(p.capitalize() for p in operation.split("_")) + "Request")
            return _sdk_call(self.client, operation, request(**kwargs))
        except HuaweiAuthError:
            raise
        except Exception:
            raise HuaweiAuthError("Huawei IAM discovery failed") from None

    def scopes(self, *, regions=None, project_id=None, account_id=None):
        region_page = self.call("keystone_list_regions")
        if (region_page.get("links") or {}).get("next"):
            raise HuaweiAuthError("IAM returned incomplete region discovery")
        known = {item["id"] for item in region_page.get("regions") or []
                 if _REGION.fullmatch(item.get("id") or "")}
        if not known:
            raise HuaweiAuthError("IAM returned no regions")
        selected = known if regions == "all" else set(regions or [])
        if selected - known:
            raise HuaweiAuthError("Requested Huawei region was not returned by IAM")
        if project_id and project_id != "all":
            projects = [self.call("keystone_show_project", project_id=project_id).get("project") or {}]
            if projects[0].get("id") != project_id:
                raise HuaweiAuthError("IAM did not return the requested project")
        else:
            page = self.call("keystone_list_auth_projects")
            if (page.get("links") or {}).get("next"):
                raise HuaweiAuthError("IAM returned incomplete project discovery")
            projects = page.get("projects") or []
        scopes, skipped = {}, []
        for project in projects:
            pid, name, domain = project.get("id"), project.get("name") or "", project.get("domain_id")
            if project.get("enabled") is False or project.get("is_domain"):
                continue
            if account_id and domain != account_id:
                skipped.append({"project_id": pid, "reason": "project_account_mismatch"})
                continue
            # IAM regional subprojects use REGION_suffix names. Match against
            # IAM's region catalog, not a guessed or hard-coded region list.
            matches = [r for r in known if name == r or name.startswith(r + "_")]
            if len(matches) != 1 or not pid or not domain:
                skipped.append({"project_id": pid, "reason": "project_region_or_account_unresolved"})
                continue
            region = matches[0]
            if selected and region not in selected:
                continue
            scopes[(region, pid)] = dict(region=region, project_id=pid, account_id=domain)
        if not scopes:
            raise HuaweiAuthError("No accessible IAM projects match the requested region/project scope")
        return [scopes[key] for key in sorted(scopes)], skipped
