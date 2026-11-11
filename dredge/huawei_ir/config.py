"""Huawei authentication settings. SDK imports and credential lookup are lazy."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Optional


@dataclass
class HuaweiAuthConfig:
    region_name: Optional[str] = None
    project_id: Optional[str] = None
    access_key_id: Optional[str] = field(default=None, repr=False)
    secret_access_key: Optional[str] = field(default=None, repr=False)
    security_token: Optional[str] = field(default=None, repr=False)
    # SDK credential-file section: "basic" or "basic.<name>".
    profile_name: Optional[str] = None
    credential_provider: Optional[Callable[[], Any]] = field(default=None, repr=False)
    enterprise_project_id: str = "0"
    timeout: int = 20

    def __post_init__(self):
        self.region_name = self.region_name or os.getenv("HUAWEICLOUD_SDK_REGION")
        self.project_id = self.project_id or os.getenv("HUAWEICLOUD_SDK_PROJECT_ID")
        if not self.region_name or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)+", self.region_name):
            raise ValueError("Set a valid Huawei region_name or HUAWEICLOUD_SDK_REGION")
        if bool(self.access_key_id) != bool(self.secret_access_key):
            raise ValueError("Huawei explicit authentication requires both AK and SK")
        if self.security_token and not self.access_key_id:
            raise ValueError("An explicit Huawei security_token requires explicit AK and SK")
        if sum(bool(x) for x in (self.access_key_id, self.profile_name, self.credential_provider)) > 1:
            raise ValueError("Choose explicit Huawei credentials, a profile, or a credential_provider")
        if not isinstance(self.timeout, int) or isinstance(self.timeout, bool) or self.timeout <= 0:
            raise ValueError("Huawei timeout must be a positive integer")
