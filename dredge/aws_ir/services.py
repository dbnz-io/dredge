from __future__ import annotations

import boto3


class AwsServiceRegistry:
    """
    Central place to create and share boto3 clients/resources.
    """

    def __init__(self, session: boto3.Session, region: str = None) -> None:
        self._session = session
        # When set, every client this registry creates is bound to this region
        # (used for multi-region fan-out via .regional()). None = session default.
        self._region = region

        # Lazily initialized clients
        self._iam = None
        self._ec2 = None
        self._s3control = None
        self._s3 = None
        self._lambda = None
        self._cloudtrail = None
        self._kms = None
        self._guardduty = None
        self._logs = None
        self._tagging = None
        self._rds = None
        self._ecs = None
        self._secretsmanager = None
        self._events = None
        self._ssm = None
        self._securityhub = None
        self._accessanalyzer = None
        self._awsconfig = None
        self._sts = None
        self._ecr = None
        self._codebuild = None

    def _client(self, name: str, **kw):
        """Create a boto3 client, defaulting its region to this registry's
        bound region (if any) so .regional() registries hit the right endpoint."""
        if "region_name" not in kw and self._region:
            kw["region_name"] = self._region
        return self._session.client(name, **kw)

    def regional(self, region: str) -> "AwsServiceRegistry":
        """A fresh registry whose clients are all bound to `region` — used for
        multi-region fan-out (e.g. running regional review checks per region)."""
        return AwsServiceRegistry(self._session, region=region)

    @property
    def iam(self):
        if self._iam is None:
            self._iam = self._client("iam")
        return self._iam

    @property
    def ec2(self):
        if self._ec2 is None:
            self._ec2 = self._client("ec2")
        return self._ec2

    @property
    def s3control(self):
        if self._s3control is None:
            self._s3control = self._client("s3control")
        return self._s3control

    @property
    def s3(self):
        if self._s3 is None:
            self._s3 = self._client("s3")
        return self._s3

    @property
    def lambda_(self):
        if self._lambda is None:
            self._lambda = self._client("lambda")
        return self._lambda

    @property
    def cloudtrail(self):
        if self._cloudtrail is None:
            self._cloudtrail = self._client("cloudtrail")
        return self._cloudtrail

    def cloudtrail_for_region(self, region: str):
        """A CloudTrail client bound to a specific region, cached per region.

        LookupEvents is a regional API, so multi-region hunts create one client
        per region and query each regional endpoint."""
        if not hasattr(self, "_cloudtrail_by_region"):
            self._cloudtrail_by_region = {}
        if region not in self._cloudtrail_by_region:
            self._cloudtrail_by_region[region] = self._client(
                "cloudtrail", region_name=region
            )
        return self._cloudtrail_by_region[region]

    def resolve_enabled_regions(self):
        """Regions actually usable by this account for CloudTrail. Uses EC2
        DescribeRegions (enabled / opt-in-not-required regions only) so we don't
        fan out to disabled regions that would just error; falls back to
        botocore's static CloudTrail region list if DescribeRegions is denied."""
        import botocore.exceptions
        try:
            resp = self.ec2.describe_regions(
                Filters=[{"Name": "opt-in-status", "Values": ["opt-in-not-required", "opted-in"]}]
            )
            regions = sorted(r["RegionName"] for r in resp.get("Regions", []))
            if regions:
                return regions
        except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError):
            pass
        return sorted(self._session.get_available_regions("cloudtrail"))

    @property
    def kms(self):
        if self._kms is None:
            self._kms = self._client("kms")
        return self._kms

    @property
    def guardduty(self):
        if self._guardduty is None:
            self._guardduty = self._client("guardduty")
        return self._guardduty

    @property
    def logs(self):
        if self._logs is None:
            self._logs = self._client("logs")
        return self._logs

    @property
    def tagging(self):
        if self._tagging is None:
            self._tagging = self._client("resourcegroupstaggingapi")
        return self._tagging

    @property
    def rds(self):
        if self._rds is None:
            self._rds = self._client("rds")
        return self._rds

    @property
    def ecs(self):
        if self._ecs is None:
            self._ecs = self._client("ecs")
        return self._ecs

    @property
    def secretsmanager(self):
        if self._secretsmanager is None:
            self._secretsmanager = self._client("secretsmanager")
        return self._secretsmanager

    @property
    def events(self):
        if self._events is None:
            self._events = self._client("events")
        return self._events

    @property
    def ssm(self):
        if self._ssm is None:
            self._ssm = self._client("ssm")
        return self._ssm

    @property
    def securityhub(self):
        if self._securityhub is None:
            self._securityhub = self._client("securityhub")
        return self._securityhub

    @property
    def accessanalyzer(self):
        if self._accessanalyzer is None:
            self._accessanalyzer = self._client("accessanalyzer")
        return self._accessanalyzer

    @property
    def awsconfig(self):
        if self._awsconfig is None:
            self._awsconfig = self._client("config")
        return self._awsconfig

    @property
    def sts(self):
        if self._sts is None:
            self._sts = self._client("sts")
        return self._sts

    @property
    def ecr(self):
        if self._ecr is None:
            self._ecr = self._client("ecr")
        return self._ecr

    @property
    def codebuild(self):
        if self._codebuild is None:
            self._codebuild = self._client("codebuild")
        return self._codebuild
