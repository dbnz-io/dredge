"""Huawei metadata checks. Evidence contains selected fields, never raw configs."""
from datetime import datetime, timezone
import ipaddress
import re

CRITICAL_PORTS = (21, 22, 23, 445, 1433, 2375, 3306, 3389, 5432, 5900, 6379, 9200, 11211, 27017)


def parse_time(value):
    try:
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(value / 1000 if value > 100_000_000_000 else value, timezone.utc)
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed
    except (ValueError, TypeError, AttributeError, OverflowError, OSError):
        return None


class HuaweiReviewChecks:
    def _field(self, item, key, rid):
        value = item.get(key)
        expected = {"enabled": bool, "status": bool, "encrypted": bool, "enable_ssl": bool,
            "enable_master_volume_encryption": bool, "is_support_validate": bool,
            "minimum_password_length": int, "keep_days": int, "ttl_in_days": int,
            "addresses": dict, "public_ips": list, "endpoints": list, "mode": str}.get(key)
        if value is None or (expected and type(value) is not expected):
            self._unknown(rid, key + "_not_returned")
            return None
        return value

    def _users(self):
        account = self._account()
        if account:
            yield from self._items("iam", "keystone_list_users", "users", domain_id=account)

    def iam_login(self):
        for user in self._users():
            uid = user["id"]
            if user.get("enabled") is False or user.get("access_mode") == "programmatic":
                continue
            if user.get("access_mode") not in ("default", "console") or user.get("enabled") is not True:
                self._unknown(uid, "user_access_mode_or_enabled_state_unknown")
                continue
            response = self._call("iam", "show_user_login_protect", user_id=uid, absent=("IAM.0004",))
            if response is None:
                continue
            protection = response.get("login_protect") or {}
            enabled = False if response.get("_absent") else self._field(protection, "enabled", uid)
            method = protection.get("verification_method")
            if enabled is False or (enabled is True and method in ("sms", "email")):
                self._emit("HIGH" if enabled is False else "MEDIUM", "IAM::User", uid,
                    "Console login protection is disabled" if enabled is False else "Console login uses SMS/email verification",
                    "Enable virtual MFA login protection; review federated-user MFA separately at the identity provider.",
                    detail={"enabled": enabled, "verification_method": method})
            elif enabled is True and method != "vmfa":
                self._unknown(uid, "login_verification_method_unknown")

    def iam_admin(self):
        account = self._account()
        if not account:
            return
        for group in self._items("iam", "keystone_list_groups", "groups", domain_id=account):
            roles = self._items("iam", "keystone_list_domain_permissions_for_group", "roles",
                                domain_id=account, group_id=group["id"])
            for role in roles:
                privileged = role.get("name") in ("te_admin", "secu_admin") or role.get("display_name") in (
                    "Tenant Administrator", "Security Administrator")
                policy = role.get("policy") or {}
                for statement in policy.get("Statement", policy.get("statement")) or []:
                    actions = statement.get("Action") or statement.get("action") or []
                    effect = statement.get("Effect") or statement.get("effect")
                    if isinstance(actions, str):
                        actions = [actions]
                    if effect == "Allow" and any(a in ("*", "*:*:*", "iam:*:*") for a in actions):
                        privileged = True
                if privileged:
                    self._emit("HIGH", "IAM::Group", group["id"], "Group has an account-wide administrator grant",
                        "Review group membership and effective permissions, including conditions, denies, and IAM v5 assignments.",
                        detail={"role_id": role.get("id"), "role_name": role.get("display_name") or role.get("name"),
                                "assessment": "grant_review_required_not_effective_permission_evaluation"})

    def iam_keys(self):
        now = datetime.now(timezone.utc)
        for user in self._users():
            for key in self._items("iam", "list_permanent_access_keys", "credentials", user_id=user["id"], id_key="access"):
                if key.get("status") == "inactive":
                    continue
                created = parse_time(key.get("create_time"))
                if key.get("status") != "active" or not created:
                    self._unknown(user["id"], "access_key_status_or_creation_time_unknown")
                elif (now - created).days >= self.options["key_age_days"]:
                    self._emit("MEDIUM", "IAM::User", user["id"], "Active permanent access key exceeds the age threshold",
                        "Review use and ownership; rotate the key or replace it with temporary credentials.",
                        detail={"key_suffix": (key.get("access") or "")[-4:], "age_days": (now - created).days,
                                "threshold_days": self.options["key_age_days"], "last_used_not_assessed": True})

    def iam_agencies(self):
        account = self._account()
        if not account:
            return
        for agency in self._items("iam", "list_agencies", "agencies", domain_id=account, mode="page"):
            trust = self._field(agency, "trust_domain_id", agency["id"])
            if trust and trust != account:
                self._emit("MEDIUM", "IAM::Agency", agency["id"], "Agency trusts another account",
                    "Verify the trusted account and assigned permissions are still required and authorized.",
                    detail={"trusted_account_id": trust, "duration": agency.get("duration")})

    def iam_password(self):
        account = self._account()
        if not account:
            return
        response = self._call("iam", "show_domain_password_policy", domain_id=account)
        if response is not None:
            length = self._field(response.get("password_policy") or {}, "minimum_password_length", account)
            if isinstance(length, int) and length < self.options["min_password_length"]:
                self._emit("MEDIUM", "IAM::Account", account, "IAM password minimum is below the assessment baseline",
                    "Increase the minimum password length and enforce MFA; apply the organization's authentication policy.",
                    detail={"minimum_password_length": length, "baseline": self.options["min_password_length"]})

    def _buckets(self):
        for bucket in self._items("obs", "listBuckets", "buckets", mode="obs", id_key="name"):
            region = bucket.get("location")
            if not isinstance(region, str) or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)+", region):
                self._unknown(bucket.get("name"), "bucket_region_not_returned")
                continue
            yield bucket["name"], region

    def obs_public(self):
        for name, region in self._buckets():
            value = self._call("obs", "getBucketPublicStatus", bucketName=name, obs_region=region)
            if value is None:
                continue
            if self._field(value, "status", name) is True:
                self._emit("HIGH", "OBS::Bucket", name, "OBS reports the bucket as public",
                    "Review public access and remove unintended grants; enable public-access blocking.", region=region)

    def obs_block(self):
        for name, region in self._buckets():
            value = self._call("obs", "getBucketPublicAccessBlock", bucketName=name, obs_region=region)
            if value is not None:
                fields = ("blockPublicAcls", "ignorePublicAcls", "blockPublicPolicy", "restrictPublicBuckets")
                disabled = [field for field in fields if value.get(field) is False]
                if any(type(value.get(field)) is not bool for field in fields):
                    self._unknown(name, "public_access_block_fields_not_returned")
                if disabled:
                    self._emit("MEDIUM", "OBS::Bucket", name, "Bucket public-access blocking is incomplete",
                        "Enable the applicable public-access blocks; this finding alone does not prove public access.",
                        detail={"disabled": disabled}, region=region)

    def obs_encryption(self):
        for name, region in self._buckets():
            value = self._call("obs", "getBucketEncryption", bucketName=name, obs_region=region,
                               absent=("ServerSideEncryptionConfigurationNotFoundError",))
            if value is not None:
                if value.get("_absent") or not value.get("encryption"):
                    self._emit("MEDIUM", "OBS::Bucket", name, "Bucket has no default encryption configuration",
                        "Configure default bucket encryption; existing objects and per-object encryption are not inspected.", region=region)

    def obs_logging(self):
        for name, region in self._buckets():
            value = self._call("obs", "getBucketLogging", bucketName=name, obs_region=region)
            if value is not None and not value.get("targetBucket"):
                self._emit("LOW", "OBS::Bucket", name, "Bucket access logging has no target",
                    "Enable access logging where required and verify complementary CTS data-event coverage.", region=region)

    def _rules(self):
        return self._items("vpc", "list_security_group_rules", "security_group_rules", mode="page_info")

    def _rule_network(self, rule):
        prefix = rule.get("remote_ip_prefix")
        if not prefix:
            if rule.get("remote_group_id") or rule.get("remote_address_group_id"):
                return None
            return ipaddress.ip_network("::/0" if str(rule.get("ethertype")).lower() == "ipv6" else "0.0.0.0/0")
        try:
            return ipaddress.ip_network(prefix, strict=False)
        except ValueError:
            self._unknown(rule.get("id"), "invalid_rule_network")
            return None

    def vpc_ports(self):
        for rule in self._rules():
            if rule.get("direction") not in ("ingress", "egress") or rule.get("action") not in ("allow", "deny") or type(rule.get("enabled")) is not bool:
                self._unknown(rule.get("id"), "rule_direction_action_or_enabled_state_unknown")
                continue
            if rule.get("direction") != "ingress" or rule.get("action") == "deny" or rule.get("enabled") is False:
                continue
            network = self._rule_network(rule)
            if network is None or network.prefixlen != 0:
                continue
            protocol = str(rule.get("protocol") or "any").lower()
            if protocol not in ("tcp", "udp", "6", "17", "any", "-1"):
                continue
            ports = []
            try:
                ranges = [(1, 65535)] if not rule.get("multiport") else [
                    tuple(map(int, part.split(":"))) if ":" in part else (int(part), int(part))
                    for part in rule["multiport"].split(",")]
                if any(len(pair) != 2 or not 1 <= pair[0] <= pair[1] <= 65535 for pair in ranges):
                    raise ValueError()
                ports = [p for p in CRITICAL_PORTS if any(lo <= p <= hi for lo, hi in ranges)]
            except (ValueError, TypeError):
                self._unknown(rule.get("id"), "invalid_rule_ports")
            if ports:
                self._emit("HIGH", "VPC::SecurityGroup", rule.get("security_group_id"), "Rule permits critical ports from all addresses",
                    "Restrict source networks and ports; verify effective rule priority, routes, and public address exposure.",
                    detail={"rule_id": rule.get("id"), "source": str(network), "protocol": protocol, "ports": ports})

    def vpc_ips(self):
        for rule in self._rules():
            network = self._rule_network(rule)
            matches = [str(ip) for ip in self.options["ips"] if network is not None and ip.version == network.version and ip.overlaps(network)]
            if matches:
                self._emit("INFO", "VPC::SecurityGroup", rule.get("security_group_id"), "Security-group rule overlaps an incident IP/CIDR",
                    "Review the rule and its change history; overlap is a hunting lead, not proof of malicious traffic.",
                    detail={"rule_id": rule.get("id"), "source": str(network), "matches": matches,
                            "direction": rule.get("direction"), "action": rule.get("action"), "enabled": rule.get("enabled")})

    def vpc_flow(self):
        vpcs = list(self._items("vpc", "list_vpcs", "vpcs", mode="page_info"))
        if not vpcs:
            return
        before = len(self._check["errors"])
        logs = list(self._items("vpc_flow", "list_flow_logs", "flow_logs", mode="marker"))
        if len(self._check["errors"]) != before or self._check["uninspected"]:
            return
        if any(log.get("status") is None or log.get("admin_state") is None for log in logs):
            self._unknown("project", "flow_log_state_not_returned")
        elif not any(log["status"] == "ACTIVE" and log["admin_state"] is True for log in logs):
            self._emit("MEDIUM", "VPC::Project", self.project_id, "No active VPC flow logs were returned",
                "Enable appropriate flow logs and verify coverage for each VPC/subnet/interface.", detail={"vpcs": len(vpcs)})

    def _servers(self):
        return self._items("ecs", "list_servers_details", "servers", mode="marker", total="count")

    def ecs_public(self):
        for server in self._servers():
            addresses = self._field(server, "addresses", server["id"])
            if addresses is None:
                continue
            public = [entry.get("addr") for entries in addresses.values() for entry in entries
                      if entry.get("os_ext_ip_stype", entry.get("OS-EXT-IPS:type")) == "floating"]
            if public:
                self._emit("MEDIUM", "ECS::Server", server["id"], "Server has a public floating address",
                    "Verify public connectivity is required and inspect security groups, host controls, and network paths.",
                    detail={"public_addresses": public})

    def evs_encryption(self):
        for volume in self._items("evs", "list_volumes", "volumes", mode="offset", total="count"):
            if self._field(volume, "encrypted", volume["id"]) is False:
                self._emit("MEDIUM", "EVS::Volume", volume["id"], "Disk is not encrypted",
                    "Migrate sensitive data to an encrypted volume and review snapshot/backup encryption.")

    def _instances(self):
        return self._items("rds", "list_instances", "instances", mode="offset", total="total_count")

    def rds_public(self):
        for db in self._instances():
            if self._field(db, "public_ips", db["id"]):
                self._emit("HIGH", "RDS::Instance", db["id"], "Database has a public address",
                    "Prefer private connectivity and verify ingress restrictions and database authentication.", detail={"public_ips": db["public_ips"]})

    def rds_encryption(self):
        for db in self._instances():
            if "disk_encryption_id" not in db or db["disk_encryption_id"] is None:
                self._unknown(db["id"], "disk_encryption_id_not_returned")
            elif db["disk_encryption_id"] == "":
                self._emit("MEDIUM", "RDS::Instance", db["id"], "Database storage has no encryption key",
                    "Use encrypted database storage and verify backup encryption.")

    def rds_ssl(self):
        for db in self._instances():
            if self._field(db, "enable_ssl", db["id"]) is False:
                self._emit("MEDIUM", "RDS::Instance", db["id"], "Database SSL is disabled",
                    "Enable TLS and configure clients to verify the server certificate.")

    def rds_backups(self):
        for db in self._instances():
            if db.get("type") == "Replica":
                continue
            response = self._call("rds", "show_backup_policy", instance_id=db["id"])
            if response is not None:
                days = self._field(response.get("backup_policy") or {}, "keep_days", db["id"])
                if isinstance(days, int) and days < self.options["min_backup_days"]:
                    self._emit("MEDIUM", "RDS::Instance", db["id"], "Automated backup retention is below the baseline",
                        "Increase backup retention and test restoration; review separate backup policies if applicable.",
                        detail={"keep_days": days, "baseline_days": self.options["min_backup_days"]})

    def _clusters(self):
        return self._items("cce", "list_clusters", "items", detail="true", id_key="metadata.uid")

    def cce_public(self):
        for cluster in self._clusters():
            rid = (cluster.get("metadata") or {}).get("uid")
            endpoints = self._field(cluster.get("status") or {}, "endpoints", rid)
            if endpoints is not None and any(e.get("type") == "External" for e in endpoints):
                self._emit("HIGH", "CCE::Cluster", rid, "Cluster exposes an external API endpoint",
                    "Restrict API access networks and audit Kubernetes RBAC; external does not imply anonymous access.",
                    detail={"allowed_cidrs": ((cluster.get("spec") or {}).get("public_access") or {}).get("cidrs")})

    def cce_auth(self):
        for cluster in self._clusters():
            rid = (cluster.get("metadata") or {}).get("uid")
            mode = self._field((cluster.get("spec") or {}).get("authentication") or {}, "mode", rid)
            if mode == "x509":
                self._emit("HIGH", "CCE::Cluster", rid, "Cluster uses legacy x509 authentication mode",
                    "Review access and migrate to a supported cluster with RBAC authentication.")
            elif mode is not None and mode not in ("rbac", "authenticating_proxy"):
                self._unknown(rid, "unknown_cluster_authentication_mode")

    def cce_encryption(self):
        for cluster in self._clusters():
            rid = (cluster.get("metadata") or {}).get("uid")
            if self._field(cluster.get("spec") or {}, "enable_master_volume_encryption", rid) is False:
                self._emit("MEDIUM", "CCE::Cluster", rid, "Control-plane volume encryption is disabled",
                    "Use encrypted control-plane volumes where supported; this does not assess Kubernetes Secret encryption.")

    def function_triggers(self):
        for function in self._items("functiongraph", "list_functions", "functions", mode="functiongraph", id_key="func_urn"):
            urn = function["func_urn"]
            for trigger in self._items("functiongraph", "list_function_triggers", "body", function_urn=urn, id_key="trigger_id"):
                if trigger.get("trigger_type_code") not in ("APIG", "DEDICATEDGATEWAY", "APIC") or trigger.get("trigger_status") == "DISABLED":
                    continue
                if trigger.get("trigger_status") != "ACTIVE":
                    self._unknown(urn, "trigger_status_unknown")
                    continue
                auth = self._field(trigger.get("event_data") or {}, "auth", urn)
                if auth == "NONE":
                    self._emit("HIGH", "FunctionGraph::Function", urn, "Active API trigger has no gateway authentication",
                        "Enable IAM/app authentication or verify an intentional public endpoint and application controls; network reachability is not tested.",
                        detail={"trigger_id": trigger.get("trigger_id"), "trigger_type": trigger.get("trigger_type_code")})

    def _trackers(self):
        return self._items("cts", "list_trackers", "trackers", tracker_type="system")

    def cts_enabled(self):
        before = len(self._check["errors"])
        trackers = list(self._trackers())
        if self._check["errors"][before:] or self._check["uninspected"]:
            return
        if any(t.get("status") not in ("enabled", "disabled", "error") for t in trackers):
            self._unknown("project", "tracker_status_unknown")
        elif not any(t["status"] == "enabled" for t in trackers):
            self._emit("HIGH", "CTS::Project", self.project_id, "No enabled system tracker was returned",
                "Enable CTS management-event tracking and verify organization-level coverage where applicable.")

    def cts_archive(self):
        for tracker in self._trackers():
            obs = tracker.get("obs_info") or {}
            lts = tracker.get("lts") or {}
            if not obs.get("bucket_name") and lts.get("is_lts_enabled") is False:
                self._emit("MEDIUM", "CTS::Tracker", tracker.get("id"), "System tracker has no OBS/LTS archive destination",
                    "Configure durable audit-log export and retention beyond the CTS event-history window.")
            elif not obs.get("bucket_name") and lts.get("is_lts_enabled") is None:
                self._unknown(tracker.get("id"), "tracker_archive_configuration_unknown")

    def cts_integrity(self):
        for tracker in self._trackers():
            if not (tracker.get("obs_info") or {}).get("bucket_name"):
                continue
            if self._field(tracker, "is_support_validate", tracker.get("id")) is False:
                self._emit("MEDIUM", "CTS::Tracker", tracker.get("id"), "Archived trace-file integrity validation is disabled",
                    "Enable trace-file validation and protect the archive against alteration and deletion.")

    def lts_retention(self):
        for group in self._items("lts", "list_log_groups", "log_groups", id_key="log_group_id"):
            days = self._field(group, "ttl_in_days", group["log_group_id"])
            if isinstance(days, int) and 0 < days < self.options["min_log_retention_days"]:
                self._emit("MEDIUM", "LTS::LogGroup", group["log_group_id"], "Log-group retention is below the baseline",
                    "Retain logs for the required investigation window; review stream overrides and exported archives separately.",
                    detail={"ttl_in_days": days, "baseline_days": self.options["min_log_retention_days"]})
            elif not isinstance(days, int) or days <= 0:
                self._unknown(group["log_group_id"], "log_group_retention_unknown")

    def hss_protection(self):
        hosts = {h["host_id"]: h for h in self._items("hss", "list_host_status", "data_list", mode="offset",
                  total="total_num", id_key="host_id", enterprise_project_id="all_granted_eps", region=self.services.config.region_name)}
        if self._check["errors"] or self._check["uninspected"]:
            return
        for server in self._servers():
            if server.get("status") != "ACTIVE":
                continue
            host = hosts.get(server["id"])
            if host is None:
                self._emit("MEDIUM", "ECS::Server", server["id"], "Running server was not returned by HSS inventory",
                    "Verify HSS enrollment, permissions, and any alternative endpoint protection.", detail={"assessment": "coverage_gap"})
            elif host.get("protect_status") in ("closed", "protection_exception") or host.get("agent_status") in (
                    "not_installed", "offline", "install_failed", "installing"):
                self._emit("HIGH", "HSS::Host", server["id"], "Host protection or agent is not healthy",
                    "Restore HSS protection and investigate unexpected agent/protection changes.",
                    detail={"protect_status": host.get("protect_status"), "agent_status": host.get("agent_status")})
            elif host.get("protect_status") != "opened" or host.get("agent_status") not in ("online", "installed"):
                self._unknown(server["id"], "host_protection_state_unknown")

    def secmaster_workspaces(self):
        workspaces = list(self._items("secmaster", "list_workspaces", "workspaces", mode="offset", total="count", project_id=self.project_id))
        if not workspaces and not self._check["errors"] and not self._check["uninspected"]:
            self._emit("LOW", "SecMaster::Project", self.project_id, "No SecMaster workspace was returned for this project",
                "Verify local or centralized SIEM/SOAR coverage; workspace presence alone does not establish detection coverage.",
                detail={"assessment": "coverage_review_required"})

    def _recent(self, kind, rid, value):
        created = parse_time(value)
        if created is None:
            self._unknown(rid, "creation_time_not_returned")
        elif created >= self.options["incident_start"]:
            self._emit("INFO", kind, rid, "Resource was created after the incident start",
                "Correlate creation with CTS and change records; creation time alone does not establish compromise.", created_time=created.isoformat())

    def recent_iam(self):
        for user in self._users():
            response = self._call("iam", "show_user", user_id=user["id"])
            if response is not None:
                self._recent("IAM::User", user["id"], (response.get("user") or {}).get("create_time"))
        account = self._account()
        if account:
            for agency in self._items("iam", "list_agencies", "agencies", mode="page", domain_id=account):
                self._recent("IAM::Agency", agency["id"], agency.get("create_time"))

    def recent_regional(self):
        for server in self._servers():
            self._recent("ECS::Server", server["id"], server.get("created"))
        for db in self._instances():
            self._recent("RDS::Instance", db["id"], db.get("created"))
        for cluster in self._clusters():
            meta = cluster.get("metadata") or {}
            self._recent("CCE::Cluster", meta.get("uid"), meta.get("creation_timestamp"))
