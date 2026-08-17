from __future__ import annotations

import boto3
from typing import Optional, TYPE_CHECKING

from .config import DredgeConfig
from .auth import AwsAuthConfig, AwsSessionFactory
from .aws_ir import AwsIRNamespace

# github_ir/gcp_ir/k8s_ir are imported lazily below, inside Dredge.__init__,
# not here at module top level. Each pulls in a genuinely heavy transitive
# dependency (github_ir -> PyGithub, gcp_ir -> google-cloud-logging's
# google-auth/grpc chain, k8s_ir -> the kubernetes client + its own
# grpc/protobuf stack, ~120MB uncompressed for k8s_ir alone) that a
# consumer using only dredge.aws_ir shouldn't have to import -- or ship in
# a size-constrained deployment target like a Lambda package -- just
# because `import dredge` touched the class definition. TYPE_CHECKING-only
# imports here keep real type checkers (mypy/pyright) happy without
# executing at runtime.
if TYPE_CHECKING:
    from .github_ir import GitHubIRNamespace
    from .gcp_ir import GcpIRNamespace
    from .k8s_ir import K8sIRNamespace

class Dredge:
    def __init__(
        self,
        *,
        session: Optional[boto3.Session] = None,
        auth: Optional[AwsAuthConfig] = None,
        config: Optional[DredgeConfig] = None,
        github_config: Optional["GitHubIRConfig"] = None,  # type: ignore[name-defined]
        gcp_config: Optional["GcpIRConfig"] = None,
        k8s_config: Optional["K8sAuthConfig"] = None,  # type: ignore[name-defined]
    ) -> None:
        self.config = config or DredgeConfig(
            region_name=(auth.region_name if auth else None)
        )

        if session is not None and auth is not None:
            raise ValueError("Provide either 'session' or 'auth', not both.")

        if session is not None:
            self._session = session
        else:
            auth_cfg = auth or AwsAuthConfig(region_name=self.config.region_name)
            factory = AwsSessionFactory(auth_cfg)
            self._session = factory.get_session()

        # AWS IR namespace
        self.aws_ir = AwsIRNamespace(self._session, self.config)

        # GitHub IR namespace (optional; only if config is provided) --
        # imported here, not at module top level, so a consumer that never
        # passes github_config never imports PyGithub at all.
        self.github_ir: Optional["GitHubIRNamespace"]
        if github_config is not None:
            from .github_ir import GitHubIRNamespace
            self.github_ir = GitHubIRNamespace(github_config)
        else:
            self.github_ir = None

        # GCP IR namespace (optional; only if config is provided) --
        # imported here, not at module top level, so a consumer that never
        # passes gcp_config never imports google-cloud-logging/google-auth.
        self.gcp_ir: Optional["GcpIRNamespace"]
        if gcp_config:
            from .gcp_ir import GcpIRNamespace
            self.gcp_ir = GcpIRNamespace(gcp_config)
        else:
            self.gcp_ir = None

        # Kubernetes IR namespace (optional; only if config is provided) --
        # imported here, not at module top level, so a consumer that never
        # passes k8s_config never imports the kubernetes client library.
        self.k8s_ir: Optional["K8sIRNamespace"]
        if k8s_config is not None:
            from .k8s_ir import K8sIRNamespace
            self.k8s_ir = K8sIRNamespace(k8s_config, self.config)
        else:
            self.k8s_ir = None