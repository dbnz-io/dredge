"""Comprehensive, read-only AWS certificate exposure audit."""

from __future__ import annotations

import base64
import hashlib
import re
import shutil
import socket
import ssl
# OpenSSL is a read-only fallback for collecting the peer's full TLS chain.
import subprocess  # nosec B404
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

import botocore.exceptions

from .models import OperationResult


_PEM_CERT_RE = re.compile(
    r"-----BEGIN CERTIFICATE-----\s*(.*?)\s*-----END CERTIFICATE-----", re.S
)
_AWS_ERRORS = (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError)


def _items(client, operation: str, key: str, **kwargs: Any) -> Iterable[Dict[str, Any]]:
    for page in client.get_paginator(operation).paginate(**kwargs):
        yield from page.get(key, [])


def parse_runtime_endpoint(value: str) -> Tuple[str, int]:
    """Parse HOST, HOST:PORT, [IPv6]:PORT, or an unbracketed IPv6 address."""
    value = value.strip()
    if not value:
        raise ValueError("Runtime endpoint cannot be empty")
    if value.startswith("["):
        match = re.fullmatch(r"\[([^]]+)](?::(\d+))?", value)
        if not match:
            raise ValueError(f"Invalid runtime endpoint: {value}")
        host, port = match.group(1), int(match.group(2) or 443)
    elif value.count(":") == 1:
        host, port_text = value.rsplit(":", 1)
        if not port_text.isdigit():
            raise ValueError(f"Invalid runtime endpoint port: {value}")
        port = int(port_text)
    elif ":" in value:
        host, port = value, 443
    else:
        host, port = value, 443
    host = host.rstrip(".").strip()
    if (not host or host.startswith("*.") or re.search(r"[\s/?#]", host)
            or not 1 <= port <= 65535):
        raise ValueError(f"Invalid runtime endpoint: {value}")
    return host, port


class AwsCertificateAudit:
    """Inventory ACM and every AWS certificate attachment supported by Dredge."""

    KEY_TYPES = [
        "RSA_1024", "RSA_2048", "RSA_3072", "RSA_4096",
        "EC_prime256v1", "EC_secp384r1", "EC_secp521r1",
    ]

    def __init__(self, services: Any) -> None:
        self.services = services

    @staticmethod
    def _pem_fingerprints(pem: str) -> List[str]:
        values: List[str] = []
        for body in _PEM_CERT_RE.findall(pem or ""):
            try:
                der = base64.b64decode(re.sub(r"\s", "", body), validate=True)
            except (ValueError, TypeError):
                continue
            values.append(hashlib.sha256(der).hexdigest())
        return values

    @staticmethod
    def _inspect_pem(
        pem: str, fingerprints: Set[str], ca_names: Set[str]
    ) -> List[Dict[str, Any]]:
        """Return certificate-level matches, including subject/issuer name hits."""
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives import hashes
        except ImportError:
            return [
                {"sha256": value, "matched_sha256_fingerprints": [value]}
                for value in AwsCertificateAudit._pem_fingerprints(pem)
                if value in fingerprints
            ]

        matches = []
        blocks = re.findall(
            r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", pem or "", re.S
        )
        for position, block in enumerate(blocks):
            body_match = _PEM_CERT_RE.search(block)
            try:
                der = base64.b64decode(
                    re.sub(r"\s", "", body_match.group(1)), validate=True
                ) if body_match else b""
            except (ValueError, TypeError):
                der = b""
            fallback_fingerprint = hashlib.sha256(der).hexdigest() if der else None
            try:
                cert = x509.load_pem_x509_certificate(block.encode())
            except ValueError:
                if fallback_fingerprint in fingerprints:
                    matches.append({
                        "position": position,
                        "subject": None,
                        "issuer": None,
                        "sha256": fallback_fingerprint,
                        "matched_ca_names": [],
                        "matched_sha256_fingerprints": [fallback_fingerprint],
                        "ioc_match": True,
                    })
                continue
            fingerprint = cert.fingerprint(hashes.SHA256()).hex()
            subject = cert.subject.rfc4514_string()
            issuer = cert.issuer.rfc4514_string()
            matched_names = sorted(
                name for name in ca_names if name in (subject + issuer).casefold()
            )
            matched_fingerprints = [fingerprint] if fingerprint in fingerprints else []
            if matched_names or matched_fingerprints:
                matches.append({
                    "position": position,
                    "subject": subject,
                    "issuer": issuer,
                    "sha256": fingerprint,
                    "matched_ca_names": matched_names,
                    "matched_sha256_fingerprints": matched_fingerprints,
                    "ioc_match": True,
                })
        return matches

    def run(
        self,
        *,
        fingerprints: Set[str],
        ca_names: Set[str],
        regions: List[str],
        max_workers: int,
        deep: bool = False,
        runtime: bool = False,
        runtime_endpoints: Optional[List[str]] = None,
        runtime_timeout: float = 5.0,
        runtime_workers: int = 8,
    ) -> OperationResult:
        has_iocs = bool(fingerprints or ca_names)
        result = OperationResult(
            operation="hunt_certificates", target="aws-acm", success=True,
            details={
                "mode": "ioc_hunt" if has_iocs else "inventory",
                "iocs": {
                    "sha256_fingerprints": sorted(fingerprints),
                    "ca_names": sorted(ca_names),
                },
                "deep_analysis": deep,
                "runtime_analysis": runtime,
            },
        )
        records: List[Dict[str, Any]] = []
        certificates: List[Dict[str, Any]] = []
        material_matches: List[Dict[str, Any]] = []
        runtime_targets: Dict[Tuple[str, int], Dict[str, List[str]]] = {}
        runtime_targets_lock = threading.Lock()
        by_region: Dict[str, Dict[str, Any]] = {}

        def target(host: Optional[str], port: int, source: str, resource: str) -> None:
            if not host:
                return
            host = host.rstrip(".").lower()
            if host.startswith("*."):
                return
            with runtime_targets_lock:
                context = runtime_targets.setdefault(
                    (host, int(port)), {"sources": [], "resources": []}
                )
                if source not in context["sources"]:
                    context["sources"].append(source)
                if resource not in context["resources"]:
                    context["resources"].append(resource)

        def regional_scan(region: str):
            registry = self.services.regional(region)
            regional_records: List[Dict[str, Any]] = []
            regional_certs: List[Dict[str, Any]] = []
            regional_matches: List[Dict[str, Any]] = []
            errors: List[str] = []
            cert_by_arn: Dict[str, Dict[str, Any]] = {}

            def certificate(arn: Optional[str]) -> Optional[Dict[str, Any]]:
                if not arn:
                    return None
                if arn in cert_by_arn:
                    return cert_by_arn[arn]
                try:
                    cert = registry.acm.describe_certificate(CertificateArn=arn).get("Certificate", {})
                except _AWS_ERRORS as exc:
                    errors.append(f"{region}: unable to describe {arn}: {exc}")
                    return None
                issuer = cert.get("Issuer") or "(unknown issuer)"
                matched_names = sorted(name for name in ca_names if name in issuer.casefold())
                entry: Dict[str, Any] = {
                    "certificate_arn": arn, "region": region,
                    "domain_name": cert.get("DomainName"),
                    "subject_alternative_names": cert.get("SubjectAlternativeNames", []),
                    "issuer": issuer, "status": cert.get("Status"),
                    "type": cert.get("Type"), "serial": cert.get("Serial"),
                    "not_before": cert.get("NotBefore"), "not_after": cert.get("NotAfter"),
                    "in_use_by": cert.get("InUseBy", []),
                    "certificate_authority_arn": cert.get("CertificateAuthorityArn"),
                    "matched_ca_names": matched_names,
                    "matched_sha256_fingerprints": [],
                }
                if fingerprints:
                    try:
                        bundle = registry.acm.get_certificate(CertificateArn=arn)
                        pem = "\n".join((bundle.get("Certificate") or "", bundle.get("CertificateChain") or ""))
                        entry["matched_sha256_fingerprints"] = sorted(
                            fingerprints.intersection(self._pem_fingerprints(pem))
                        )
                        entry["chain_matches"] = self._inspect_pem(
                            pem, fingerprints, ca_names
                        )
                    except _AWS_ERRORS as exc:
                        errors.append(f"{region}: unable to retrieve certificate material for {arn}: {exc}")
                entry["ioc_match"] = bool(
                    entry["matched_ca_names"] or entry["matched_sha256_fingerprints"]
                )
                cert_by_arn[arn] = entry
                regional_certs.append(entry)
                return entry

            try:
                for summary in _items(
                    registry.acm, "list_certificates", "CertificateSummaryList",
                    Includes={"keyTypes": self.KEY_TYPES},
                ):
                    certificate(summary.get("CertificateArn"))
            except _AWS_ERRORS as exc:
                errors.append(f"{region}: unable to list ACM certificates: {exc}")

            try:
                for lb in _items(registry.elbv2, "describe_load_balancers", "LoadBalancers"):
                    lb_arn = lb.get("LoadBalancerArn")
                    for listener in _items(
                        registry.elbv2, "describe_listeners", "Listeners", LoadBalancerArn=lb_arn
                    ):
                        if listener.get("Protocol") not in {"HTTPS", "TLS"}:
                            continue
                        listener_arn = listener.get("ListenerArn")
                        port = listener.get("Port", 443)
                        target(lb.get("DNSName"), port, "load_balancer_listener", listener_arn)
                        seen: Set[str] = set()
                        attached = list(listener.get("Certificates", []))
                        try:
                            attached.extend(_items(
                                registry.elbv2, "describe_listener_certificates", "Certificates",
                                ListenerArn=listener_arn,
                            ))
                        except _AWS_ERRORS as exc:
                            errors.append(f"{region}: unable to list listener certificates for {listener_arn}: {exc}")
                        for item in attached:
                            arn = item.get("CertificateArn")
                            if not arn or arn in seen:
                                continue
                            seen.add(arn)
                            details = certificate(arn)
                            if details:
                                for name in [details.get("domain_name"), *details.get("subject_alternative_names", [])]:
                                    target(name, port, "load_balancer_certificate_name", listener_arn)
                            regional_records.append({
                                "kind": "load_balancer_listener_certificate", "region": region,
                                "resource": listener_arn, "load_balancer": lb_arn,
                                "dns_name": lb.get("DNSName"), "port": port,
                                "certificate_arn": arn, "is_default": item.get("IsDefault"),
                                "certificate_issuer": details.get("issuer") if details else None,
                            })
            except _AWS_ERRORS as exc:
                errors.append(f"{region}: unable to inventory load balancers: {exc}")

            try:
                for item in _items(registry.apigateway, "get_domain_names", "items"):
                    arn = item.get("regionalCertificateArn") or item.get("certificateArn")
                    target(item.get("domainName"), 443, "apigateway_v1_domain", item.get("domainName"))
                    details = certificate(arn) if not item.get("certificateArn") else None
                    regional_records.append({
                        "kind": "apigateway_v1_domain", "region": region,
                        "resource": item.get("domainName"), "certificate_arn": arn,
                        "certificate_region": "us-east-1" if item.get("certificateArn") else region,
                        "certificate_issuer": details.get("issuer") if details else None,
                    })
            except _AWS_ERRORS as exc:
                errors.append(f"{region}: unable to inventory API Gateway v1 domains: {exc}")

            try:
                for item in _items(registry.apigatewayv2, "get_domain_names", "Items"):
                    domain = item.get("DomainName")
                    target(domain, 443, "apigateway_v2_domain", domain)
                    for config in item.get("DomainNameConfigurations", []):
                        arn = config.get("CertificateArn")
                        details = certificate(arn)
                        regional_records.append({
                            "kind": "apigateway_v2_domain", "region": region,
                            "resource": domain, "certificate_arn": arn,
                            "certificate_issuer": details.get("issuer") if details else None,
                        })
            except _AWS_ERRORS as exc:
                errors.append(f"{region}: unable to inventory API Gateway v2 domains: {exc}")

            if deep:
                try:
                    for ca in _items(
                        registry.acmpca, "list_certificate_authorities", "CertificateAuthorities"
                    ):
                        arn = ca.get("Arn")
                        regional_records.append({
                            "kind": "private_certificate_authority", "region": region,
                            "resource": arn, "status": ca.get("Status"), "type": ca.get("Type"),
                            "key_algorithm": ca.get("KeyAlgorithm"),
                            "signing_algorithm": ca.get("SigningAlgorithm"),
                        })
                        if ca.get("Status") in {"DELETED", "PENDING_CERTIFICATE", "CREATING"}:
                            continue
                        try:
                            bundle = registry.acmpca.get_certificate_authority_certificate(
                                CertificateAuthorityArn=arn
                            )
                            pem = "\n".join((bundle.get("Certificate") or "", bundle.get("CertificateChain") or ""))
                            for match in self._inspect_pem(pem, fingerprints, ca_names):
                                regional_matches.append({
                                    "kind": "private_ca_chain_match", "region": region,
                                    "resource": arn, "source": "acm-pca", **match,
                                })
                        except _AWS_ERRORS as exc:
                            errors.append(f"{region}: unable to retrieve Private CA {arn}: {exc}")
                except _AWS_ERRORS as exc:
                    errors.append(f"{region}: unable to list Private CAs: {exc}")
            return regional_certs, regional_records, regional_matches, errors

        workers = min(max_workers, len(regions))
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(regional_scan, region): region for region in regions}
            for future in as_completed(futures):
                region = futures[future]
                try:
                    region_certs, region_records, region_matches, errors = future.result()
                except Exception as exc:  # one region must not abort the audit
                    region_certs, region_records, region_matches = [], [], []
                    errors = [f"{region}: unexpected certificate audit error: {exc}"]
                certificates.extend(region_certs)
                records.extend(region_records)
                material_matches.extend(region_matches)
                result.errors.extend(errors)
                by_region[region] = {
                    "certificate_count": len(region_certs),
                    "resource_reference_count": len(region_records),
                    "errors": errors,
                }

        try:
            for dist in _items(self.services.cloudfront, "list_distributions", "Items"):
                arn = dist.get("ARN")
                viewer = dist.get("ViewerCertificate", {})
                target(dist.get("DomainName"), 443, "cloudfront_distribution", arn)
                for alias in dist.get("Aliases", {}).get("Items", []):
                    target(alias, 443, "cloudfront_alias", arn)
                origins = []
                for origin in dist.get("Origins", {}).get("Items", []):
                    custom = origin.get("CustomOriginConfig")
                    origins.append({
                        "id": origin.get("Id"), "domain_name": origin.get("DomainName"),
                        "https_port": custom.get("HTTPSPort", 443) if custom else None,
                        "origin_protocol_policy": custom.get("OriginProtocolPolicy") if custom else None,
                    })
                    if custom and custom.get("OriginProtocolPolicy") in {"https-only", "match-viewer"}:
                        target(origin.get("DomainName"), custom.get("HTTPSPort", 443), "cloudfront_custom_origin", arn)
                records.append({
                    "kind": "cloudfront_distribution", "region": "global", "resource": arn,
                    "certificate_arn": viewer.get("ACMCertificateArn"),
                    "iam_certificate_id": viewer.get("IAMCertificateId"),
                    "domain_name": dist.get("DomainName"),
                    "aliases": dist.get("Aliases", {}).get("Items", []), "origins": origins,
                })
        except _AWS_ERRORS as exc:
            result.errors.append(f"global: unable to inventory CloudFront distributions: {exc}")

        if deep:
            try:
                for summary in _items(
                    self.services.iam, "list_server_certificates", "ServerCertificateMetadataList"
                ):
                    name = summary.get("ServerCertificateName")
                    try:
                        item = self.services.iam.get_server_certificate(
                            ServerCertificateName=name
                        ).get("ServerCertificate", {})
                        metadata = item.get("ServerCertificateMetadata", {})
                        arn = metadata.get("Arn")
                        records.append({
                            "kind": "iam_server_certificate", "region": "global",
                            "resource": arn, "name": name, "path": metadata.get("Path"),
                            "expiration": metadata.get("Expiration"),
                        })
                        pem = "\n".join((item.get("CertificateBody") or "", item.get("CertificateChain") or ""))
                        for match in self._inspect_pem(pem, fingerprints, ca_names):
                            material_matches.append({
                                "kind": "iam_server_certificate_match", "region": "global",
                                "resource": arn, "source": "iam", **match,
                            })
                    except _AWS_ERRORS as exc:
                        result.errors.append(f"global: unable to retrieve IAM server certificate {name}: {exc}")
            except _AWS_ERRORS as exc:
                result.errors.append(f"global: unable to list IAM server certificates: {exc}")

        for value in runtime_endpoints or []:
            host, port = parse_runtime_endpoint(value)
            target(host, port, "operator_supplied", f"{host}:{port}")

        runtime_records: List[Dict[str, Any]] = []
        if runtime:
            with ThreadPoolExecutor(max_workers=runtime_workers) as executor:
                futures = {
                    executor.submit(
                        self._probe_runtime, key, context, fingerprints, ca_names, runtime_timeout
                    ): key
                    for key, context in runtime_targets.items()
                }
                for future in as_completed(futures):
                    host, port = futures[future]
                    try:
                        runtime_records.append(future.result())
                    except Exception as exc:
                        result.errors.append(f"runtime: {host}:{port}: {exc}")
            records.extend(runtime_records)

        certificates.sort(key=lambda item: (
            item["issuer"].casefold(), item["region"], item["certificate_arn"] or ""
        ))
        certificate_matches = [item for item in certificates if item["ioc_match"]]
        runtime_matches = [item for item in runtime_records if item.get("ioc_match")]
        ca_counts: Dict[str, int] = {}
        for item in certificates:
            ca_counts[item["issuer"]] = ca_counts.get(item["issuer"], 0) + 1
        ca_summary = [
            {"certificate_authority": issuer, "certificate_count": count}
            for issuer, count in sorted(ca_counts.items(), key=lambda pair: (-pair[1], pair[0].casefold()))
        ]
        potential_matches = certificate_matches + material_matches + runtime_matches
        result.details.update({
            "certificates": certificates,
            "records": records,
            "matches": potential_matches,
            "potential_matches": potential_matches,
            "ca_summary": ca_summary,
            "by_region": {region: by_region[region] for region in sorted(by_region)},
            "runtime_targets": len(runtime_targets) if runtime else 0,
            "limitations": [
                "Issuer/subject name matches are investigative leads, not proof of exposure.",
                "A clean result does not prove absence of exposure; review errors and coverage.",
                "Workload trust stores, outbound TLS, and historical certificates are not inspected.",
            ],
            "statistics": {
                "regions_scanned": len(regions),
                "certificates_scanned": len(certificates),
                "certificate_authorities": len(ca_summary),
                "resource_references": len([r for r in records if r.get("kind") != "runtime_tls_endpoint"]),
                "runtime_endpoints": len(runtime_records),
                "matches": len(potential_matches),
                "errors": len(result.errors),
            },
        })
        if result.errors:
            result.success = False
        return result

    @staticmethod
    def _probe_runtime(
        endpoint: Tuple[str, int], context: Dict[str, List[str]], fingerprints: Set[str],
        ca_names: Set[str], timeout: float,
    ) -> Dict[str, Any]:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization

        host, port = endpoint
        label = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
        der_chain: List[bytes] = []
        # Deliberately collect even broken/untrusted incident chains; trust is checked separately below.
        unverified = ssl._create_unverified_context()  # nosec B323
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with unverified.wrap_socket(raw, server_hostname=host) as tls:
                tls_version = tls.version()
                cipher_info = tls.cipher()
                cipher = cipher_info[0] if cipher_info else None
                get_chain = getattr(tls, "get_unverified_chain", None)
                if get_chain:
                    for item in get_chain():
                        encoded = item if isinstance(item, bytes) else item.public_bytes()
                        if isinstance(encoded, str):
                            encoded = x509.load_pem_x509_certificate(encoded.encode()).public_bytes(
                                serialization.Encoding.DER
                            )
                        der_chain.append(encoded)
                else:
                    leaf = tls.getpeercert(binary_form=True)
                    if leaf:
                        der_chain.append(leaf)

        if not hasattr(ssl.SSLSocket, "get_unverified_chain"):
            openssl = shutil.which("openssl")
            if not openssl:
                raise RuntimeError("full chain inspection requires OpenSSL on this Python version")
            # The executable is resolved by shutil.which and arguments are not shell-expanded.
            completed = subprocess.run(  # nosec B603
                [openssl, "s_client", "-connect", label, "-servername", host, "-showcerts"],
                input=b"", capture_output=True, timeout=timeout, check=False,
            )
            output = (completed.stdout + completed.stderr).decode("utf-8", errors="replace")
            blocks = re.findall(
                r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", output, re.S
            )
            if blocks:
                der_chain = [
                    x509.load_pem_x509_certificate(block.encode()).public_bytes(
                        serialization.Encoding.DER
                    ) for block in blocks
                ]
        certificates = []
        for position, der in enumerate(der_chain):
            cert = x509.load_der_x509_certificate(der)
            fingerprint = cert.fingerprint(hashes.SHA256()).hex()
            subject, issuer = cert.subject.rfc4514_string(), cert.issuer.rfc4514_string()
            matched_names = sorted(
                name for name in ca_names if name in (subject + issuer).casefold()
            )
            certificates.append({
                "position": position, "subject": subject, "issuer": issuer,
                "sha256": fingerprint,
                "matched_sha256_fingerprints": [fingerprint] if fingerprint in fingerprints else [],
                "matched_ca_names": matched_names,
            })
        chain_trusted = True
        trust_error = None
        try:
            verified = ssl.create_default_context()
            verified.check_hostname = False
            with socket.create_connection((host, port), timeout=timeout) as raw:
                with verified.wrap_socket(raw, server_hostname=host):
                    pass
        except (OSError, ssl.SSLError) as exc:
            chain_trusted = False
            trust_error = str(exc)
        return {
            "kind": "runtime_tls_endpoint", "region": "runtime", "resource": label,
            "host": host, "port": port, "sources": context["sources"],
            "referenced_resources": context["resources"], "tls_version": tls_version,
            "cipher": cipher, "certificates": certificates,
            "chain_trusted_by_local_store": chain_trusted,
            "trust_error": trust_error,
            "ioc_match": any(
                item["matched_sha256_fingerprints"] or item["matched_ca_names"]
                for item in certificates
            ),
        }
