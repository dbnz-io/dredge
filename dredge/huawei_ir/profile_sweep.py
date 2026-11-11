"""Shared Huawei profile selection and serialized SSO authorization."""
from .auth import HuaweiAuthError, HuaweiCredentialFactory
from .config import HuaweiAuthConfig
from .profiles import validate_sso_profile
from .sso import AgencyCredentialProvider, SsoSession


def _safe_error(exc):
    return str(exc) if isinstance(exc, HuaweiAuthError) else "Huawei operation failed; no credential or response data logged"


def _selection(value, name):
    if value is None or value == "all":
        return value
    values = [value] if isinstance(value, str) else value
    if not isinstance(values, (list, tuple)) or not values or any(not isinstance(v, str) or not v for v in values):
        raise ValueError(f"{name} must be all, a name, or a nonempty list of names")
    if "all" in values:
        raise ValueError(f"{name}: all cannot be combined with named selections")
    return list(dict.fromkeys(values))


def _identities(label, profile, sessions, sso_login, timeout, cache_dir, notify, errors):
    if profile["kind"] != "sso":
        config = HuaweiAuthConfig(region_name=profile.get("region") or "cn-north-4",
                                 profile_name=label if profile["kind"] == "basic" else None, timeout=timeout)
        factory = HuaweiCredentialFactory(config)
        credentials = lambda: factory.get_credentials(require_project=False)
        credentials()
        yield {"account_id": None, "agency_urn": None, "credentials": credentials}
        return
    validate_sso_profile(profile)
    key = (profile["sso_region"], profile["sso_start_url"].rstrip("/"), profile["session_name"])
    if key not in sessions:
        sessions[key] = SsoSession(profile, timeout=timeout, cache_dir=cache_dir, notify=notify)
    session = sessions[key]
    account_key = "account_id" if profile.get("account_id") else "account_name"
    agency_key = "agency_urn" if profile.get("agency_urn") else "permission_set_name"
    accounts = list(session.pages("list_accounts", "account_list", allow_login=sso_login))
    accounts = {a["account_id"]: a for a in accounts
                if profile[account_key] == "all" or a.get(account_key) == profile[account_key]}
    if not accounts:
        raise HuaweiAuthError("SSO account selector matched no assigned accounts")
    for account_id in sorted(accounts):
        try:
            agencies = list(session.pages("list_account_agencies", "agency_list", account_id=account_id))
            agencies = {a["agency_urn"]: a for a in agencies
                        if profile[agency_key] == "all" or a.get(agency_key) == profile[agency_key]}
            if not agencies:
                raise HuaweiAuthError("SSO agency/permission-set selector matched no assignments")
        except Exception as exc:
            errors.append(f"Account {account_id}: " + _safe_error(exc))
            continue
        for urn in sorted(agencies):
            try:
                credentials = AgencyCredentialProvider(session, account_id, urn)
                credentials()
                yield {"account_id": account_id, "agency_urn": urn, "credentials": credentials}
            except Exception as exc:
                errors.append(f"Account {account_id}, agency {urn}: " + _safe_error(exc))


