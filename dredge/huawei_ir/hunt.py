"""Read-only Huawei configuration scans and explicitly targeted content scans."""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import time
from datetime import datetime, timedelta

from ..secret_scanning import ContentBudget, _SecretBucket, _emit_secret_text, _hash_secret
from .auth import HuaweiAuthError
from .models import OperationResult
from .services import HuaweiServiceError

API_ERRORS = (HuaweiAuthError, HuaweiServiceError)
CONFIG_SCANNERS = ("functiongraph", "ecs_user_data", "cae", "codearts", "modelarts",
                   "servicestage", "dataartsstudio")


def _positive(**values):
    for name, value in values.items():
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            raise ValueError(f"{name} must be a positive integer")


def _targets(values, name):
    if isinstance(values, str):
        raise ValueError(f"{name} must be a list of targets")
    values = list(values or [])
    if any(not isinstance(v, str) or not v.strip() for v in values):
        raise ValueError(f"{name} contains an empty or invalid target")
    return list(dict.fromkeys(values))


class _Scan:
    def __init__(self, services, name, budget, bucket, result, max_resources):
        self.services, self.name, self.budget = services, name, budget
        self.bucket, self.result, self.max_resources = bucket, result, max_resources

    def source(self, resource, location=None):
        return {"service": self.name, "region": self.services.config.region_name,
                "resource_id": resource, "location_type": location or self.name}

    def call(self, operation, **params):
        if not self.budget.request():
            return None
        service = "ecs" if self.name == "ecs_user_data" else self.name
        try:
            return self.services.call(service, operation, **params)
        except API_ERRORS as exc:
            self.result.add_error(str(exc))
            return None

    def resource(self):
        if self.budget.examined >= self.max_resources:
            self.budget.stop("max_resources")
            return False
        self.budget.examined += 1
        return True

    def emit(self, value, resource, location=None):
        if time.monotonic() - self.budget.started >= self.budget.max_seconds:
            self.budget.stop("max_seconds")
        if self.budget.reasons:
            return
        text = value if isinstance(value, str) else json.dumps(value)
        size = len(text.encode("utf-8"))
        if size > self.budget.max_bytes - self.budget.bytes_reserved:
            self.budget.stop("max_bytes")
            return
        self.budget.bytes_read += size
        self.budget.bytes_reserved += size
        _emit_secret_text(text, self.source(resource, location), self.bucket)
        self.budget.scanned += 1

    def uninspected(self, resource, reason):
        self.budget.skipped += 1
        self.result.details["uninspected"].append({**self.source(resource), "reason": reason})


def _functiongraph(scan):
    marker, seen = "0", set()
    while not scan.budget.reasons:
        page = scan.call("list_functions", marker=marker, maxitems="100")
        if page is None:
            return
        items = page.get("functions") or []
        for item in items:
            if not scan.resource():
                return
            urn = item["func_urn"]
            data = scan.call("show_function_config", function_urn=urn)
            if data is None:
                continue
            env = data.get("user_data") or "{}"
            try:
                env = json.loads(env) if isinstance(env, str) else env
            except ValueError:
                scan.uninspected(urn, "unparseable_environment")
                continue
            if not isinstance(env, dict):
                scan.uninspected(urn, "unparseable_environment")
                continue
            encrypted = data.get("encrypted_user_data") not in (None, "", "{}", {})
            visible = {}
            for key, value in env.items():
                if key.startswith("_encrypt_") or (isinstance(value, str) and re.fullmatch(r"\*+", value)):
                    encrypted = True
                else:
                    visible[key] = value
            if encrypted:
                scan.uninspected(urn, "encrypted_or_masked_environment")
            scan.emit(visible, urn)
        next_marker = page.get("next_marker")
        if not items or next_marker in (None, 0, "0", -1, "-1", ""):
            return
        next_marker = str(next_marker)
        if next_marker == marker or next_marker in seen:
            scan.budget.stop("pagination_stalled")
            return
        seen.add(marker)
        marker = next_marker


def _ecs(scan):
    marker, seen = None, set()
    while not scan.budget.reasons:
        page = scan.call("list_servers_details", limit=100, **({"marker": marker} if marker else {}))
        if page is None:
            return
        items = page.get("servers") or []
        if not items:
            return
        for item in items:
            if not scan.resource():
                return
            resource = item["id"]
            if resource in seen:
                scan.budget.stop("pagination_stalled")
                return
            seen.add(resource)
            detail = scan.call("show_server", server_id=resource)
            if detail is None:
                continue
            server = detail.get("server") or {}
            data = server.get("os_ext_srv_att_ruser_data")
            if data is None:
                scan.uninspected(resource, "user_data_not_returned")
                continue
            try:
                decoded = base64.b64decode(data, validate=True).decode("utf-8")
            except (ValueError, UnicodeDecodeError, binascii.Error):
                scan.uninspected(resource, "non_text_or_invalid_user_data")
                continue
            scan.emit(decoded, resource)
        if len(items) < 100:
            return
        marker = items[-1]["id"]


def _cae(scan):
    enterprise = {"x_enterprise_project_id": scan.services.config.enterprise_project_id}
    environments = scan.call("list_environments", **enterprise)
    if environments is None:
        return
    for env in environments.get("items") or []:
        headers = {**enterprise, "x_environment_id": env["id"]}
        applications = scan.call("list_applications", **headers)
        if applications is None:
            continue
        for app in applications.get("items") or []:
            offset, seen = 0, set()
            while not scan.budget.reasons:
                page = scan.call("list_components", application_id=app["id"], limit="100",
                                 offset=str(offset), **headers)
                if page is None:
                    break
                items = page.get("items") or []
                for item in items:
                    if not scan.resource():
                        return
                    resource = f"{env['id']}/{app['id']}/{item['id']}"
                    if resource in seen:
                        scan.budget.stop("pagination_stalled")
                        return
                    seen.add(resource)
                    data = scan.call("list_component_configurations", application_id=app["id"],
                                     component_id=item["id"], display_mode="latestEffective", **headers)
                    if data is None:
                        continue
                    for config in data.get("items") or []:
                        spec = (config.get("data") or {}).get("spec") or {}
                        if config.get("type") == "env":
                            envs = spec.get("envs") or {}
                            visible = {k: v for k, v in envs.items()
                                       if not (isinstance(v, str) and re.fullmatch(r"\*+", v))}
                            if len(visible) != len(envs):
                                scan.uninspected(resource, "masked_environment")
                            scan.emit(visible, resource, "cae_environment")
                            if spec.get("env_references"):
                                scan.uninspected(resource, "secret_references_not_resolved")
                offset += len(items)
                total = page.get("total_count")
                if not items or (total is not None and offset >= total) or len(items) < 100:
                    break


def _codearts(scan):
    """Inspect readable, non-private CodeArts Pipeline parameter groups."""
    project_id = scan.services.config.project_id
    if not project_id:
        scan.result.add_error("codearts: a regional project ID is required")
        return
    offset, seen = 0, set()
    while not scan.budget.reasons:
        page = scan.call("list_variable_groups", project_id=project_id,
                         body={"offset": offset, "limit": 100, "name": ""})
        if page is None:
            return
        groups = page.get("pipeline_variable_groups") or []
        for group in groups:
            if not scan.resource():
                return
            group_id = group.get("id")
            if not group_id or group_id in seen:
                scan.budget.stop("pagination_stalled")
                return
            seen.add(group_id)
            detail = scan.call("show_variable_group_detail", project_id=project_id, id=group_id)
            if detail is None:
                continue
            visible = {}
            has_private = False
            for variable in detail.get("variables") or []:
                name = variable.get("name")
                if not name:
                    continue
                if variable.get("is_secret") is True:
                    has_private = True
                elif variable.get("is_secret") is False and variable.get("value") is not None:
                    visible[name] = variable["value"]
                else:
                    has_private = True
            resource = f"{project_id}/{group_id}"
            if has_private:
                scan.uninspected(resource, "private_or_masked_pipeline_variables")
            scan.emit(visible, resource, "codearts_pipeline_variable_group")
        offset += len(groups)
        total = page.get("total")
        if not groups or (total is not None and offset >= total):
            return


def _modelarts(scan):
    """Inspect retrievable ModelArts training-job environment settings."""
    offset, seen = 0, set()
    while not scan.budget.reasons:
        page = scan.call("list_training_jobs", body={"offset": offset, "limit": 100})
        if page is None:
            return
        items = page.get("items") or []
        for item in items:
            metadata = item.get("metadata") or {}
            job_id = metadata.get("id")
            if not job_id:
                scan.uninspected("unknown", "training_job_id_not_returned")
                continue
            if job_id in seen:
                scan.budget.stop("pagination_stalled")
                return
            seen.add(job_id)
            if not scan.resource():
                return
            detail = scan.call("show_training_job_details", training_job_id=job_id)
            if detail is None:
                continue
            spec = detail.get("spec") or {}
            envs = spec.get("environments") or []
            if isinstance(envs, list):
                for index, env in enumerate(envs):
                    if isinstance(env, dict):
                        scan.emit(env, f"{job_id}/environment/{index}", "modelarts_training_environment")
            elif isinstance(envs, dict):
                scan.emit(envs, job_id, "modelarts_training_environment")
            else:
                scan.uninspected(job_id, "unrecognized_training_environment_shape")
        offset += len(items)
        total = page.get("total")
        if not items or (total is not None and offset >= total) or len(items) < 100:
            break

    # ModelArts real-time deployment unit environments and startup commands
    # are also returned by the management API, independently of training jobs.
    offset, seen_services = 0, set()
    while not scan.budget.reasons:
        page = scan.call("list_infer_services", limit=100, offset=offset)
        if page is None:
            return
        services = page.get("data") or []
        for service in services:
            service_id = service.get("id")
            if not service_id or service_id in seen_services:
                continue
            seen_services.add(service_id)
            deployment_offset, seen_deployments = 0, set()
            while not scan.budget.reasons:
                deployments = scan.call("list_infer_deployments", service_id=service_id,
                                        limit=100, offset=deployment_offset)
                if deployments is None:
                    break
                deployment_items = deployments.get("data") or []
                for deployment in deployment_items:
                    deployment_id = deployment.get("id")
                    if not deployment_id or deployment_id in seen_deployments:
                        continue
                    seen_deployments.add(deployment_id)
                    if not scan.resource():
                        return
                    detail = scan.call("show_infer_deployment", service_id=service_id,
                                       deployment_id=deployment_id)
                    if detail is None:
                        continue
                    for unit in detail.get("unit_configs") or []:
                        if unit.get("envs"):
                            scan.emit(unit["envs"], f"{service_id}/{deployment_id}/{unit.get('name', '?')}",
                                      "modelarts_inference_environment")
                        if unit.get("cmd"):
                            scan.emit(unit["cmd"], f"{service_id}/{deployment_id}/{unit.get('name', '?')}",
                                      "modelarts_inference_command")
                deployment_offset += len(deployment_items)
                total_deployments = deployments.get("total")
                if (not deployment_items or (total_deployments is not None
                        and deployment_offset >= total_deployments) or len(deployment_items) < 100):
                    break
        offset += len(services)
        total_services = page.get("total")
        if not services or (total_services is not None and offset >= total_services) or len(services) < 100:
            return


def _servicestage(scan):
    """Inspect ServiceStage application, environment, and component variables."""
    offset = 0
    envs = []
    while not scan.budget.reasons:
        page = scan.call("show_environments", limit=100, offset=offset)
        if page is None:
            return
        items = page.get("environments") or []
        envs.extend(items)
        offset += len(items)
        total = page.get("count")
        if not items or (total is not None and offset >= total) or len(items) < 100:
            break
    offset = 0
    applications = []
    while not scan.budget.reasons:
        page = scan.call("show_applications", limit=100, offset=offset)
        if page is None:
            return
        items = page.get("applications") or []
        applications.extend(items)
        offset += len(items)
        total = page.get("count")
        if not items or (total is not None and offset >= total) or len(items) < 100:
            break
    for app in applications:
        app_id = app.get("id")
        if not app_id:
            continue
        for env in envs:
            env_id = env.get("id")
            if not env_id:
                continue
            if not scan.resource():
                return
            config = scan.call("show_application_configuration", application_id=app_id,
                               environment_id=env_id)
            if config is None:
                continue
            values = config.get("configuration") or []
            for entry in values:
                if isinstance(entry, dict):
                    scan.emit(entry, f"{app_id}/{env_id}", "servicestage_application_environment")
            component_offset = 0
            while not scan.budget.reasons:
                components = scan.call("show_components_in_application", application_id=app_id,
                                       limit=100, offset=component_offset)
                if components is None:
                    break
                records = components.get("components") or []
                for component in records:
                    component_id = component.get("id")
                    if not component_id:
                        continue
                    if not scan.resource():
                        return
                    detail = scan.call("show_component_info", application_id=app_id,
                                       component_id=component_id, expect_fields="envs,command")
                    if detail is None:
                        continue
                    if detail.get("envs"):
                        scan.emit(detail["envs"], f"{app_id}/{component_id}",
                                  "servicestage_component_environment")
                    if detail.get("command"):
                        scan.emit(detail["command"], f"{app_id}/{component_id}",
                                  "servicestage_component_command")
                component_offset += len(records)
                total = components.get("count")
                if not records or (total is not None and component_offset >= total) or len(records) < 100:
                    break


def _dataartsstudio(scan):
    """Inspect workspace variables and retrievable connection configuration."""
    offset = 0
    workspaces = []
    while not scan.budget.reasons:
        page = scan.call("list_workspaces", x_project_id=scan.services.config.project_id,
                         limit=100, offset=offset)
        if page is None:
            return
        data = page.get("data") or {}
        result = data.get("value") or {}
        items = result.get("records") or []
        workspaces.extend(items)
        offset += len(items)
        total = result.get("total")
        if not items or (total is not None and offset >= total) or len(items) < 100:
            break
    for workspace in workspaces:
        workspace_id = workspace.get("id")
        if not workspace_id:
            continue
        if not scan.resource():
            return
        env = scan.call("show_factory_env", workspace=workspace_id)
        if env is not None and env.get("params"):
            scan.emit(env["params"], workspace_id, "dataarts_workspace_environment")
        offset = 0
        while not scan.budget.reasons:
            page = scan.call("list_dataconnections", workspace=workspace_id,
                             limit="100", offset=str(offset))
            if page is None:
                break
            connections = page.get("data_connection_lists") or []
            for connection in connections:
                connection_id = connection.get("dw_id")
                if not connection_id:
                    continue
                if not scan.resource():
                    return
                detail = scan.call("show_dataconnection", workspace=workspace_id,
                                   data_connection_id=connection_id)
                if detail is not None and detail.get("dw_config"):
                    scan.emit(detail["dw_config"], f"{workspace_id}/{connection_id}",
                              "dataarts_connection_configuration")
            offset += len(connections)
            total = page.get("total_size")
            if not connections or (total is not None and offset >= total) or len(connections) < 100:
                break


def _cci(scan):
    """Inventory readable CCI Secret objects by hashes, never findings/raw values."""
    try:
        if not scan.budget.request():
            return
        namespaces = scan.services.cci_call("/apis/cci/v2/namespaces")
    except API_ERRORS as exc:
        scan.result.add_error(str(exc))
        return
    for namespace_obj in namespaces.get("items") or []:
        namespace = (namespace_obj.get("metadata") or {}).get("name")
        if not namespace:
            continue
        if not scan.resource():
            return
        token, seen = None, set()
        while not scan.budget.reasons:
            try:
                if not scan.budget.request():
                    return
                page = scan.services.cci_call(
                    f"/apis/cci/v2/namespaces/{namespace}/secrets",
                    params={"limit": 100, "continue": token},
                )
            except API_ERRORS as exc:
                scan.result.add_error(str(exc))
                break
            for secret in page.get("items") or []:
                metadata = secret.get("metadata") or {}
                secret_name = metadata.get("name")
                if not secret_name:
                    continue
                if not scan.resource():
                    return
                data = secret.get("data") or {}
                hashes = {}
                for key, encoded in data.items():
                    if not isinstance(encoded, str):
                        scan.uninspected(f"{namespace}/{secret_name}", "non_string_secret_value")
                        continue
                    try:
                        decoded = base64.b64decode(encoded, validate=True)
                    except (ValueError, binascii.Error):
                        scan.uninspected(f"{namespace}/{secret_name}", "invalid_base64_secret_value")
                        continue
                    if len(decoded) > scan.budget.max_bytes - scan.budget.bytes_reserved:
                        scan.budget.stop("max_bytes")
                        return
                    scan.budget.bytes_reserved += len(decoded)
                    scan.budget.bytes_read += len(decoded)
                    hashes[key] = hashlib.sha256(decoded).hexdigest()
                scan.result.details["inventory"].append({
                    **scan.source(f"{namespace}/{secret_name}", "cci_secret"),
                    "type": secret.get("type"), "keys": hashes,
                    "assessment": "intended_secret_storage",
                })
                scan.budget.scanned += 1
            metadata = page.get("metadata") or {}
            next_token = metadata.get("_continue") or metadata.get("continue")
            if not next_token:
                break
            if next_token in seen:
                scan.budget.stop("pagination_stalled")
                return
            seen.add(next_token)
            token = next_token
        if scan.budget.reasons:
            return
        for resource_name in ("pods", "deployments"):
            token, seen = None, set()
            while not scan.budget.reasons:
                try:
                    if not scan.budget.request():
                        return
                    page = scan.services.cci_call(
                        f"/apis/cci/v2/namespaces/{namespace}/{resource_name}",
                        params={"limit": 100, "continue": token},
                    )
                except API_ERRORS as exc:
                    scan.result.add_error(str(exc))
                    break
                for workload in page.get("items") or []:
                    metadata = workload.get("metadata") or {}
                    name = metadata.get("name", "unknown")
                    if not scan.resource():
                        return
                    spec = workload.get("spec") or {}
                    if resource_name == "deployments":
                        spec = ((spec.get("template") or {}).get("spec") or {})
                    exposed, references = {}, False
                    for container in (spec.get("initContainers") or []) + (spec.get("containers") or []):
                        envs = container.get("env") or []
                        for env in envs:
                            key = env.get("name")
                            if not key:
                                continue
                            if "value" in env:
                                exposed[key] = env["value"]
                            elif env.get("valueFrom"):
                                references = True
                        for field in ("command", "args"):
                            values = container.get(field)
                            if values:
                                exposed[f"{container.get('name', 'container')}.{field}"] = values
                    resource_id = f"{namespace}/{name}"
                    if references:
                        scan.uninspected(resource_id, "workload_secret_references_not_resolved")
                    if exposed:
                        scan.emit(exposed, resource_id, f"cci_{resource_name[:-1]}_configuration")
                metadata = page.get("metadata") or {}
                next_token = metadata.get("_continue") or metadata.get("continue")
                if not next_token:
                    break
                if next_token in seen:
                    scan.budget.stop("pagination_stalled")
                    return
                seen.add(next_token)
                token = next_token


def _obs(scan, targets, max_objects, max_object_bytes):
    seen_objects = set()
    for target in targets:
        bucket_name, prefix = target[6:].split("/", 1)
        marker, markers = None, set()
        while not scan.budget.reasons:
            if scan.budget.examined >= max_objects:
                scan.budget.stop("max_objects")
                return
            if not scan.budget.request():
                return
            try:
                page = scan.services.obs_call("listObjects", bucketName=bucket_name, prefix=prefix,
                                              marker=marker, max_keys=min(1000, max_objects - scan.budget.examined)).body
            except API_ERRORS as exc:
                scan.result.add_error(str(exc))
                break
            for item in page.get("contents") or []:
                if scan.budget.examined >= max_objects:
                    scan.budget.stop("max_objects")
                    return
                scan.budget.examined += 1
                key, size = item["key"], item.get("size", 0)
                resource = f"obs://{bucket_name}/{key}"
                if (bucket_name, key) in seen_objects:
                    scan.budget.skipped += 1
                    continue
                seen_objects.add((bucket_name, key))
                if not key.startswith(prefix):
                    scan.result.add_error("obs: response contained an object outside the requested prefix")
                    continue
                if size <= 0 or size > max_object_bytes or item.get("storageClass") in {"COLD", "DEEP_ARCHIVE"}:
                    scan.uninspected(resource, "size_or_storage_class")
                    continue
                if size > scan.budget.max_bytes - scan.budget.bytes_reserved:
                    scan.budget.stop("max_bytes")
                    return
                if not scan.budget.request():
                    return
                scan.budget.bytes_reserved += size
                try:
                    headers = {"range": f"0-{size - 1}"}
                    if item.get("etag"):
                        headers["if_match"] = item["etag"]
                    body = scan.services.obs_call("getObject", bucketName=bucket_name, objectKey=key,
                                                 headers=headers, loadStreamInMemory=False).body
                    stream = body["response"]
                    try:
                        data = stream.read(size)
                    finally:
                        stream.close()
                    scan.budget.bytes_read += len(data)
                    if len(data) != size:
                        scan.result.add_error("obs: incomplete object body")
                        continue
                    if body.get("contentEncoding") not in (None, "", "identity") or b"\x00" in data:
                        scan.uninspected(resource, "binary_or_compressed_object")
                        continue
                    try:
                        content = data.decode("utf-8")
                    except UnicodeDecodeError:
                        scan.uninspected(resource, "non_utf8_object")
                        continue
                    _emit_secret_text(content, scan.source(resource, "obs_object"), scan.bucket)
                    scan.budget.scanned += 1
                except (HuaweiAuthError, HuaweiServiceError, OSError):
                    scan.result.add_error("obs: object read failed")
            if not page.get("is_truncated"):
                break
            next_marker = page.get("next_marker")
            if not next_marker or next_marker in markers:
                scan.budget.stop("pagination_stalled")
                return
            markers.add(next_marker)
            marker = next_marker


def _lts(scan, targets, start, end, max_events):
    for target in targets:
        group, stream = target.split("/")
        body = {"start_time": str(int(start.timestamp() * 1000)),
                "end_time": str(int(end.timestamp() * 1000)), "is_desc": False,
                "highlight": False, "is_count": False, "is_iterative": False, "search_type": "init"}
        seen = set()
        while not scan.budget.reasons:
            if scan.budget.examined >= max_events:
                scan.budget.stop("max_events")
                return
            body["limit"] = min(100, max_events - scan.budget.examined)
            page = scan.call("list_logs", log_group_id=group, log_stream_id=stream, body=dict(body))
            if page is None:
                break
            logs = page.get("logs") or []
            for entry in logs:
                if scan.budget.examined >= max_events:
                    scan.budget.stop("max_events")
                    return
                scan.budget.examined += 1
                scan.emit(entry.get("content") or "", target, "lts_log")
                if scan.budget.reasons:
                    return
            # A completed query page is not necessarily the final page.
            cursor = page.get("scroll_id")
            incomplete = page.get("is_query_complete") is False
            if not incomplete and (not logs or (len(logs) < body["limit"] and not cursor)):
                break
            last = logs[-1] if logs else {}
            line = last.get("line_num")
            stamp = (last.get("labels") or {}).get("__time__")
            position = (cursor, line, stamp)
            if (not cursor and not line) or position in seen:
                scan.budget.stop("pagination_stalled")
                break
            seen.add(position)
            body["search_type"] = "forwards"
            for key, value in (("scroll_id", cursor), ("line_num", line), ("time__", stamp)):
                body.pop(key, None)
                if value is not None:
                    body[key] = value


def validate_scan_options(*, include=None, scan_obs=None, scan_lts=None, scan_csms=None,
                          start_time=None, end_time=None, k8s_services=None,
                          scan_k8s_secrets=False, **options):
    """Shared validation, including before a multi-profile login starts."""
    selected = list(CONFIG_SCANNERS) if include is None else _targets(include, "include")
    if set(selected) - {*CONFIG_SCANNERS, "cce", "cci"}:
        raise ValueError("Unknown Huawei configuration scanner")
    obs, lts, csms = (_targets(scan_obs, "scan_obs"), _targets(scan_lts, "scan_lts"),
                      _targets(scan_csms, "scan_csms"))
    for target in obs:
        if not re.fullmatch(r"obs://[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]/[^*?\[\]\s]+", target):
            raise ValueError("OBS targets must be obs://bucket/nonempty-prefix without wildcards")
    for target in lts:
        if not re.fullmatch(r"[A-Za-z0-9_-]+/[A-Za-z0-9_-]+", target):
            raise ValueError("LTS targets must be GROUP_ID/STREAM_ID without wildcards")
    if lts:
        if any(not isinstance(t, datetime) or t.utcoffset() is None for t in (start_time, end_time)):
            raise ValueError("LTS requires timezone-aware start_time and end_time")
        if not timedelta(0) < end_time - start_time <= timedelta(hours=24):
            raise ValueError("LTS window must be greater than zero and at most 24 hours")
    elif start_time is not None or end_time is not None:
        raise ValueError("start_time/end_time require scan_lts targets")
    if "cce" in selected and k8s_services is None:
        raise ValueError("CCE scanning requires explicitly configured Kubernetes access")
    if scan_k8s_secrets and "cce" not in selected:
        raise ValueError("scan_k8s_secrets requires the cce scanner")
    _positive(**{key: options[key] for key in (
        "max_resources", "obs_max_objects", "obs_max_object_bytes", "lts_max_events",
        "content_max_bytes", "content_max_api_calls", "content_max_seconds") if key in options})
    return selected, obs, lts, csms


class HuaweiIRHunt:
    def __init__(self, services, k8s_services=None):
        self.services = services
        self.k8s_services = k8s_services

    def hunt_exposed_secrets(
        self, *, include=None, keep_raw=False, max_resources=500,
        scan_obs=None, scan_lts=None, scan_csms=None,
        start_time=None, end_time=None, obs_max_objects=100, obs_max_object_bytes=1048576,
        lts_max_events=1000, content_max_bytes=10485760,
        content_max_api_calls=100, content_max_seconds=60,
        k8s_services=None, k8s_namespace=None, scan_k8s_secrets=False,
    ):
        """One Huawei region/project. Content and secret-store access are opt-in.

        include defaults to FunctionGraph, ECS user data, CAE, and readable
        CodeArts Pipeline parameter groups. Add ``cce`` with an authenticated
        K8sServiceRegistry for the selected CCE cluster.
        CSMS values and Kubernetes Secrets are inventory, not exposure findings.
        Budgets apply per scanner across its targets; time is checked between
        requests (an in-flight request can take the configured SDK timeout).
        """
        k8s_services = k8s_services if k8s_services is not None else self.k8s_services
        selected, obs, lts, csms = validate_scan_options(
            include=include, scan_obs=scan_obs, scan_lts=scan_lts, scan_csms=scan_csms,
            start_time=start_time, end_time=end_time, k8s_services=k8s_services,
            scan_k8s_secrets=scan_k8s_secrets, max_resources=max_resources, obs_max_objects=obs_max_objects,
            obs_max_object_bytes=obs_max_object_bytes, lts_max_events=lts_max_events,
            content_max_bytes=content_max_bytes, content_max_api_calls=content_max_api_calls,
            content_max_seconds=content_max_seconds)
        result = OperationResult("hunt_exposed_secrets", self.services.config.region_name, True,
                                 {"findings": [], "inventory": [], "uninspected": [], "scanners": {}})
        bucket = _SecretBucket(keep_raw=keep_raw)
        tasks = [(name, {"functiongraph": _functiongraph, "ecs_user_data": _ecs,
                         "cae": _cae, "codearts": _codearts, "modelarts": _modelarts,
                         "servicestage": _servicestage, "dataartsstudio": _dataartsstudio,
                         "cci": _cci}.get(name))
                 for name in selected]
        if obs:
            tasks.append(("obs", lambda scan: _obs(scan, obs, obs_max_objects, obs_max_object_bytes)))
        if lts:
            tasks.append(("lts", lambda scan: _lts(scan, lts, start_time, end_time, lts_max_events)))
        if csms:
            tasks.append(("csms", lambda scan: _csms(scan, csms)))
        for name, scanner in tasks:
            budget = (ContentBudget(content_max_api_calls, content_max_bytes, content_max_seconds)
                      if name in {"obs", "lts", "csms"} else ContentBudget(2000, 64 * 1024 * 1024, 120))
            scan = _Scan(self.services, name, budget, bucket, result, max_resources)
            before = len(result.errors)
            if name == "cce":
                from ..k8s_ir.secret_sources import scan_cluster
                scan_cluster(k8s_services, scan, k8s_namespace, scan_k8s_secrets)
            elif name == "cci":
                _cci(scan)
            else:
                scanner(scan)
            result.details["scanners"][name] = {**budget.summary(), "errors": len(result.errors) - before}
        result.details["findings"] = sorted(bucket.values(), key=lambda f: (f["severity"], f["hash"]))
        result.details["complete"] = result.success and not result.details["uninspected"] and not any(
            item["truncated"] for item in result.details["scanners"].values())
        if keep_raw:
            result.details["raw_values"] = bucket.raw_by_hash
        return result


def _csms(scan, names):
    for name in names:
        if not scan.resource():
            return
        response = scan.call("show_secret_version", secret_name=name, version_id="latest")
        if response is None:
            continue
        version = response.get("version") or {}
        if not version.get("secret_string") and not version.get("secret_binary"):
            scan.uninspected(name, "secret_value_not_returned")
            continue
        # Keep intended secret storage separate from exposed-secret findings.
        for field in ("secret_string", "secret_binary"):
            value = version.get(field)
            if not value:
                continue
            size = len(value.encode("utf-8"))
            if size > scan.budget.max_bytes - scan.budget.bytes_reserved:
                scan.budget.stop("max_bytes")
                return
            scan.budget.bytes_read += size
            scan.budget.bytes_reserved += size
            scan.result.details["inventory"].append({**scan.source(name, "csms_secret"),
                                                    "field": field, "hash": _hash_secret(value),
                                                    "assessment": "intended_secret_storage"})
        scan.budget.scanned += 1
