# Roadmap

- **Azure** support (auth, IR actions, log hunting).
- **Okta** IR (suspend users, revoke sessions, hunt sign-in logs).
- **GCP** — expand beyond Cloud Logging hunting to full IR actions + coverage
  (currently in progress).
- **Kubernetes**: cloud-specific audit log hunting (EKS → CloudWatch,
  GKE → Cloud Logging) composed with `aws_ir` / `gcp_ir`.
- **Kubernetes**: pod filesystem/memory forensic capture via ephemeral debug
  containers.
- **Kubernetes**: cross-cloud credential revocation for IRSA (EKS) / Workload
  Identity (GKE/AKS) bound ServiceAccounts.
- IoC-based hunting (IP/domain/hash correlation across providers).
- Shodan + VirusTotal reintegration.
