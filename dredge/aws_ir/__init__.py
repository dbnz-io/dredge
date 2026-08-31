from __future__ import annotations

import boto3

from ..config import DredgeConfig
from .services import AwsServiceRegistry
from .response import AwsIRResponse
from .forensics import AwsIRForensics
from .hunt import AwsIRHunt      # <-- add this
from .review import AwsIRReview


class AwsIRNamespace:
    """
    Grouping for AWS IR related functionality:

        dredge.aws_ir.response...
        dredge.aws_ir.forensics...
        dredge.aws_ir.hunt...
    """

    def __init__(self, session: boto3.Session, config: DredgeConfig) -> None:
        self._services = AwsServiceRegistry(session)

        self.response = AwsIRResponse(self._services, config)
        self.forensics = AwsIRForensics(self._services, config)
        self.hunt = AwsIRHunt(self._services, config)   # <-- add this
        self.review = AwsIRReview(self._services, config, hunt=self.hunt)
