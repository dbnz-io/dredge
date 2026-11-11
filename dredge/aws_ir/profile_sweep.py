"""Shared profile selection, authentication and region discovery for AWS audits."""
from __future__ import annotations

import os
import re
import shutil
# Opt-in AWS CLI SSO login only; argv is passed directly, never to a shell.
import subprocess  # nosec B404
import sys
from dataclasses import replace

import botocore.session
from botocore.config import Config

from ..auth import AwsAuthConfig, AwsSessionFactory


_CLIENT_CONFIG = Config(connect_timeout=10, read_timeout=20,
                        retries={"mode": "standard", "max_attempts": 2})


def _safe_error(exc):
    """Credential-provider stderr and AWS error bodies may contain secrets."""
    code = getattr(exc, "response", {}).get("Error", {}).get("Code")
    suffix = f" ({code})" if isinstance(code, str) and re.fullmatch(r"[\w.-]{1,100}", code) else ""
    return type(exc).__name__ + suffix


def _profile_catalog():
    # Respect AWS_CONFIG_FILE / AWS_SHARED_CREDENTIALS_FILE without shelling out.
    # This is not a credential lookup; configuration is never copied to output.
    try:
        return botocore.session.get_session().full_config
    except Exception as exc:
        raise ValueError("Unable to read AWS profile configuration: " + _safe_error(exc)) from None


def _sso_source(profile, catalog):
    profile = profile or os.getenv("AWS_PROFILE") or os.getenv("AWS_DEFAULT_PROFILE") or "default"
    seen = set()
    while profile is not None and profile not in seen:
        seen.add(profile)
        config = catalog.get("profiles", {}).get(profile, {})
        if config.get("sso_session"):
            name = config["sso_session"]
            return ("session", name), ["--sso-session=" + name]
        if config.get("sso_start_url") and config.get("sso_region"):
            return ("legacy", config["sso_start_url"], config["sso_region"]), ["--profile=" + profile]
        profile = config.get("source_profile")
    return None


def _needs_sso_login(exc):
    return type(exc).__name__ in {"SSOTokenLoadError", "UnauthorizedSSOTokenError", "TokenRetrievalError"} or (
        getattr(exc, "response", {}).get("Error", {}).get("Code")
        in {"UnauthorizedException", "InvalidGrantException", "ExpiredToken", "ExpiredTokenException"}
    )


def _login_sso(arguments):
    executable = shutil.which("aws")
    if not executable:
        raise RuntimeError("AWS CLI is unavailable")
    # The executable is resolved locally, and arguments are passed without a shell.
    subprocess.run(  # nosec B603
        [executable, "sso", "login", *arguments], check=True, timeout=300,
        stdout=sys.stderr, stderr=sys.stderr,
    )


def _bootstrap_region(auth, profile, catalog):
    profile = profile or os.getenv("AWS_PROFILE") or os.getenv("AWS_DEFAULT_PROFILE") or "default"
    config = catalog.get("profiles", {}).get(profile, {})
    sso = catalog.get("sso_sessions", {}).get(config.get("sso_session"), {})
    region = (auth.region_name or os.getenv("AWS_DEFAULT_REGION") or os.getenv("AWS_REGION")
              or config.get("region") or config.get("sso_region") or sso.get("sso_region"))
    if region:
        return region
    arn = auth.role_arn or config.get("role_arn", "")
    partition = arn.split(":")[1] if arn.startswith("arn:") else "aws"
    return {"aws-cn": "cn-north-1", "aws-us-gov": "us-gov-west-1"}.get(partition, "us-east-1")


def _authenticate(auth, profile, catalog):
    region = _bootstrap_region(auth, profile, catalog)
    factory = AwsSessionFactory(replace(auth, profile_name=profile, region_name=region))
    session = factory.get_session()
    identity = session.client("sts", region_name=region, config=_CLIENT_CONFIG).get_caller_identity()
    return factory, region, {"account_id": identity["Account"], "principal_arn": identity["Arn"]}


def _prepare_profiles(auth, profiles, regions, max_workers):
    auth = auth or AwsAuthConfig()
    if auth.region_name == "all" or auth.profile_name == "all":
        raise ValueError("Pass 'all' via profiles/regions, not AwsAuthConfig")
    if not isinstance(max_workers, int) or isinstance(max_workers, bool) or not 1 <= max_workers <= 32:
        raise ValueError("max_workers must be between 1 and 32")
    if regions is not None and regions != "all":
        if isinstance(regions, str) or not regions or any(
            not isinstance(region, str) or not re.fullmatch(r"[a-z]{2}(?:-[a-z0-9]+)+-\d+", region)
            for region in regions
        ):
            raise ValueError("regions must be 'all' or a nonempty list of region names")
        regions = list(dict.fromkeys(regions))
    if profiles is not None and profiles != "all" and (
        isinstance(profiles, str) or not profiles or any(not isinstance(p, str) or not p for p in profiles)
    ):
        raise ValueError("profiles must be 'all', None, or a nonempty list of names")
    if profiles is not None and any((auth.access_key_id, auth.secret_access_key, auth.session_token)):
        raise ValueError("Named/all-profile scanning cannot be combined with explicit AWS credentials")
    catalog = _profile_catalog()
    selected = (sorted(catalog.get("profiles", {})) if profiles == "all"
                else list(dict.fromkeys(profiles)) if profiles is not None else [auth.profile_name])
    if not selected:
        raise ValueError("No configured AWS profiles found")
    return auth, catalog, selected, regions


def _authenticated_profiles(auth, catalog, selected, sso_login):
    """Serialize credential/MFA prompts; hand each session to one worker."""
    login_attempts = {}
    for profile in selected:
        label = profile if profile is not None else "<default-chain>"
        record = {"authenticated": False, "regions": {}, "errors": []}
        try:
            factory, bootstrap, identity = _authenticate(auth, profile, catalog)
        except Exception as initial:
            source = _sso_source(profile, catalog)
            if sso_login and source and _needs_sso_login(initial):
                key, arguments = source
                if key not in login_attempts:
                    try:
                        _login_sso(arguments)
                        login_attempts[key] = True
                    except Exception as login_error:
                        login_attempts[key] = False
                        record["errors"].append("SSO login failed: " + _safe_error(login_error))
                if login_attempts[key]:
                    try:
                        factory, bootstrap, identity = _authenticate(auth, profile, catalog)
                    except Exception as retry_error:
                        record["errors"].append("authentication failed: " + _safe_error(retry_error))
                else:
                    record["errors"].append("shared SSO login was unsuccessful")
            else:
                record["errors"].append("authentication failed: " + _safe_error(initial))
                if source:
                    record["login_hint"] = "Run aws sso login for this profile/session, or add --sso-login"
            if record["errors"]:
                yield label, record, None, None
                continue
        record.update(identity)
        record["authenticated"] = True
        yield label, record, factory, bootstrap


def _resolve_regions(factory, bootstrap, regions):
    if regions != "all":
        return list(regions or [bootstrap])
    session = factory.get_session()
    response = session.client("ec2", region_name=bootstrap, config=_CLIENT_CONFIG).describe_regions(
        AllRegions=False,
        Filters=[{"Name": "opt-in-status", "Values": ["opt-in-not-required", "opted-in"]}],
    )
    selected = sorted({entry["RegionName"] for entry in response.get("Regions", [])
                       if entry.get("OptInStatus") in (None, "opted-in", "opt-in-not-required")})
    if not selected:
        raise ValueError("region discovery returned no enabled regions")
    return selected
