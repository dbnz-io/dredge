from __future__ import annotations

import boto3


class AwsServiceRegistry:
    """
    Central place to create and share boto3 clients/resources.
    """

    def __init__(self, session: boto3.Session) -> None:
        self._session = session

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

    @property
    def iam(self):
        if self._iam is None:
            self._iam = self._session.client("iam")
        return self._iam

    @property
    def ec2(self):
        if self._ec2 is None:
            self._ec2 = self._session.client("ec2")
        return self._ec2

    @property
    def s3control(self):
        if self._s3control is None:
            self._s3control = self._session.client("s3control")
        return self._s3control

    @property
    def s3(self):
        if self._s3 is None:
            self._s3 = self._session.client("s3")
        return self._s3

    @property
    def lambda_(self):
        if self._lambda is None:
            self._lambda = self._session.client("lambda")
        return self._lambda

    @property
    def cloudtrail(self):
        if self._cloudtrail is None:
            self._cloudtrail = self._session.client("cloudtrail")
        return self._cloudtrail

    @property
    def kms(self):
        if self._kms is None:
            self._kms = self._session.client("kms")
        return self._kms

    @property
    def guardduty(self):
        if self._guardduty is None:
            self._guardduty = self._session.client("guardduty")
        return self._guardduty

    @property
    def logs(self):
        if self._logs is None:
            self._logs = self._session.client("logs")
        return self._logs

    @property
    def tagging(self):
        if self._tagging is None:
            self._tagging = self._session.client("resourcegroupstaggingapi")
        return self._tagging

    @property
    def rds(self):
        if self._rds is None:
            self._rds = self._session.client("rds")
        return self._rds

    @property
    def ecs(self):
        if self._ecs is None:
            self._ecs = self._session.client("ecs")
        return self._ecs

    @property
    def secretsmanager(self):
        if self._secretsmanager is None:
            self._secretsmanager = self._session.client("secretsmanager")
        return self._secretsmanager

    @property
    def events(self):
        if self._events is None:
            self._events = self._session.client("events")
        return self._events

    @property
    def ssm(self):
        if self._ssm is None:
            self._ssm = self._session.client("ssm")
        return self._ssm

    @property
    def securityhub(self):
        if self._securityhub is None:
            self._securityhub = self._session.client("securityhub")
        return self._securityhub

    @property
    def accessanalyzer(self):
        if self._accessanalyzer is None:
            self._accessanalyzer = self._session.client("accessanalyzer")
        return self._accessanalyzer

    @property
    def awsconfig(self):
        if self._awsconfig is None:
            self._awsconfig = self._session.client("config")
        return self._awsconfig

    @property
    def sts(self):
        if self._sts is None:
            self._sts = self._session.client("sts")
        return self._sts

    @property
    def ecr(self):
        if self._ecr is None:
            self._ecr = self._session.client("ecr")
        return self._ecr
