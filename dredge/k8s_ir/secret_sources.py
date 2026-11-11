"""CCE uses the standard Kubernetes API and independently configured RBAC."""
from __future__ import annotations

import base64
import binascii

from kubernetes.client.exceptions import ApiException
from urllib3.exceptions import HTTPError

from ..secret_scanning import _hash_secret


def scan_cluster(services, scan, namespace=None, include_secrets=False):
    kinds = [("core_v1", "pod"), ("core_v1", "config_map"),
             ("apps_v1", "deployment"), ("apps_v1", "stateful_set"),
             ("apps_v1", "daemon_set"), ("apps_v1", "replica_set"),
             ("batch_v1", "job"), ("batch_v1", "cron_job")]
    if include_secrets:
        kinds.append(("core_v1", "secret"))
    for api, kind in kinds:
        continuation, seen = None, set()
        while not scan.budget.reasons:
            if not scan.budget.request():
                return
            params = {"limit": 100, "_request_timeout": (20, 20)}
            if continuation:
                params["_continue"] = continuation
            method = f"list_{kind}_for_all_namespaces"
            if namespace:
                method = f"list_namespaced_{kind}"
                params["namespace"] = namespace
            try:
                response = getattr(getattr(services, api), method)(**params).to_dict()
            except (ApiException, HTTPError, OSError):
                # Kubernetes exception bodies can echo workload configuration.
                scan.result.add_error(f"cce: unable to list {kind}")
                break
            for item in response.get("items") or []:
                if not scan.resource():
                    return
                metadata = item.get("metadata") or {}
                resource = f"{metadata.get('namespace', '')}/{kind}/{metadata.get('name', '')}"
                if kind in {"config_map", "secret"}:
                    _data(scan, item, resource, kind)
                    continue
                spec = item.get("spec") or {}
                if kind == "cron_job":
                    spec = (spec.get("job_template") or {}).get("spec") or {}
                if kind != "pod":
                    spec = (spec.get("template") or {}).get("spec") or {}
                for group in ("containers", "init_containers", "ephemeral_containers"):
                    for container in spec.get(group) or []:
                        location = f"{resource}/{group}/{container.get('name', '')}"
                        env = {entry["name"]: entry["value"] for entry in container.get("env") or []
                               if entry.get("value") is not None}
                        scan.emit(env, location, "kubernetes_environment")
                        for command in (container.get("command") or []) + (container.get("args") or []):
                            scan.emit(command, location, "kubernetes_command")
            continuation = (response.get("metadata") or {}).get("_continue")
            if not continuation:
                break
            if continuation in seen:
                scan.budget.stop("pagination_stalled")
                break
            seen.add(continuation)


def _data(scan, item, resource, kind):
    data = dict(item.get("data") or {})
    encoded = data if kind == "secret" else item.get("binary_data") or {}
    decoded = {} if kind == "secret" else data
    for key, value in encoded.items():
        try:
            decoded[key] = base64.b64decode(value, validate=True).decode("utf-8")
        except (ValueError, UnicodeDecodeError, binascii.Error):
            scan.uninspected(resource, "non_text_or_invalid_base64")
    if kind == "config_map":
        scan.emit(decoded, resource, "kubernetes_config_map")
        # ConfigMaps often store entire scripts/YAML files in a single value.
        for value in decoded.values():
            scan.emit(value, resource, "kubernetes_config_map_content")
        return
    for key, value in decoded.items():
        size = len(value.encode("utf-8"))
        if size > scan.budget.max_bytes - scan.budget.bytes_reserved:
            scan.budget.stop("max_bytes")
            return
        scan.budget.bytes_read += size
        scan.budget.bytes_reserved += size
        scan.result.details["inventory"].append({**scan.source(resource, "kubernetes_secret"),
                                                "key_name": key, "hash": _hash_secret(value),
                                                "assessment": "intended_secret_storage"})
    scan.budget.scanned += 1
