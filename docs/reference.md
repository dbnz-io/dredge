# Command & feature reference

Every command dredge exposes, grouped by provider and bucket, generated from the
CLI itself. For a command's full options, run `dredge <provider> <bucket> <command> --help`.

- **hunt** — read-only investigation
- **response** — containment / mutating (supports the global `--dry-run`)
- **forensics** — evidence capture

Library equivalents live under `d.<provider>_ir.<bucket>.<method>` and return an
[`OperationResult`](library/README.md#operationresult). See the per-provider
library pages: [AWS](library/aws.md) · [GitHub](library/github.md) ·
[Kubernetes](library/kubernetes.md).

### AWS — Review

| Command | Description |
|---|---|
| `dredge aws review ec2` | Review EC2/network (world-open critical ports, public snapshots, IMDSv1, SGs referencing an IP) |
| `dredge aws review ecs` | Review ECS (services with ECS Exec / execute-command enabled) |
| `dredge aws review full` | Full security review across every service + org controls (tier-1; add --deep for tier-2) |
| `dredge aws review iam` | Review IAM (admins, console-without-MFA, weak role trust, stale access keys) |
| `dredge aws review lambda` | Review Lambda (public function URLs) |
| `dredge aws review org` | Review org/account controls (GuardDuty, CloudTrail, VPC flow logs, Security Hub, Access Analyzer) |
| `dredge aws review rds` | Review RDS (public instances, storage encryption) |
| `dredge aws review recent` | Review resources created since --incident-start (IAM users/roles, Lambda, S3) |
| `dredge aws review s3` | Review S3 (public buckets, default encryption) |

### AWS — Hunt

| Command | Description |
|---|---|
| `dredge aws hunt access-analyzer` | List IAM Access Analyzer findings |
| `dredge aws hunt cloudtrail` | Hunt CloudTrail events with simple filters |
| `dredge aws hunt cloudtrail-multi-user` | Hunt CloudTrail events for a list of users (repeatable --user and/or --users-file) |
| `dredge aws hunt cloudwatch-logs` | Run a CloudWatch Logs Insights query |
| `dredge aws hunt config-history` | Get AWS Config resource configuration history |
| `dredge aws hunt exposed-secrets` | Scan Lambda/ECS/SSM/EC2 user-data/CodeBuild for plaintext secrets |
| `dredge aws hunt guardduty` | List GuardDuty findings |
| `dredge aws hunt query-cloudtrail-logs` | Filter/project fields from CloudTrail log files already on disk (offline, no AWS calls) |
| `dredge aws hunt security-groups-by-ip` | Find security groups with ingress/egress rules covering one or more IPs |
| `dredge aws hunt security-hub` | Query Security Hub findings |
| `dredge aws hunt user-activity-by-ip` | Hunt one user's CloudTrail activity, classifying each event by whether its source IP is in an allowlist |

### AWS — Response

| Command | Description |
|---|---|
| `dredge aws response block-nacl-cidrs` | Add DENY rules for CIDRs to all NACLs in a VPC |
| `dredge aws response block-s3-account` | Block S3 public access at account level |
| `dredge aws response block-s3-bucket` | Make an S3 bucket private / block public access |
| `dredge aws response block-s3-object` | Make a specific S3 object private |
| `dredge aws response cloudtrail-status` | Check CloudTrail trail status and configuration |
| `dredge aws response delete-access-key` | Delete an IAM access key |
| `dredge aws response delete-mfa-devices` | Deactivate and delete MFA devices for a user |
| `dredge aws response delete-user` | Delete an IAM user |
| `dredge aws response detach-iam-policy` | Detach a managed policy from a user or role |
| `dredge aws response disable-access-key` | Disable an IAM access key |
| `dredge aws response disable-eventbridge-rule` | Disable an EventBridge rule |
| `dredge aws response disable-kms-key` | Disable a KMS key |
| `dredge aws response disable-lambda` | Throttle a Lambda function to zero concurrency |
| `dredge aws response disable-role` | Disable an IAM role |
| `dredge aws response disable-secret` | Schedule a Secrets Manager secret for deletion |
| `dredge aws response disable-user` | Disable an IAM user |
| `dredge aws response enable-vpc-flow-logs` | Enable VPC flow logs |
| `dredge aws response iam-credential-report` | Generate and retrieve IAM credential report |
| `dredge aws response isolate-ec2` | Network-isolate EC2 instances (forensic SG) |
| `dredge aws response isolate-rds` | Isolate an RDS instance (empty SG, disable public access) |
| `dredge aws response quarantine-s3-bucket` | Block public access and apply deny-all policy to an S3 bucket |
| `dredge aws response revoke-active-sessions` | Invalidate active sessions for a user via deny policy |
| `dredge aws response schedule-kms-deletion` | Schedule a KMS key for deletion |
| `dredge aws response ssm-session-history` | Retrieve completed SSM session history |
| `dredge aws response stop-ec2` | Stop EC2 instances (can be restarted) |
| `dredge aws response stop-ecs-service` | Scale an ECS service to 0 desired tasks |
| `dredge aws response stop-ecs-task` | Force-stop a running ECS task |
| `dredge aws response tag-resources` | Apply tags to AWS resources by ARN |
| `dredge aws response terminate-ec2` | Terminate EC2 instances (snapshot EBS volumes first by default) |
| `dredge aws response terminate-ssm-sessions` | Terminate all active SSM sessions on an instance |

### AWS — Forensics

| Command | Description |
|---|---|
| `dredge aws forensics download-s3-logs` | Download log objects from an S3 bucket/prefix into one flat local folder |

### Kubernetes — Hunt

| Command | Description |
|---|---|
| `dredge k8s hunt events` | Search Kubernetes Events |
| `dredge k8s hunt pods-by-service-account` | List pods running under a ServiceAccount |
| `dredge k8s hunt privileged-pods` | Flag pods with elevated host access |
| `dredge k8s hunt role-bindings-for-subject` | Find RoleBindings/ClusterRoleBindings referencing a subject |

### Kubernetes — Response

| Command | Description |
|---|---|
| `dredge k8s response cordon-node` | Mark a node unschedulable |
| `dredge k8s response delete-node` | Remove a Node object from the cluster (not the underlying VM) |
| `dredge k8s response delete-pod` | Force-delete a pod |
| `dredge k8s response delete-secret` | Delete a Secret |
| `dredge k8s response delete-service-account` | Disable then delete a ServiceAccount |
| `dredge k8s response disable-service-account` | Delete a ServiceAccount's tokens and bindings |
| `dredge k8s response drain-node` | Cordon a node and evict its pods |
| `dredge k8s response label-resource` | Apply labels to a pod/node/namespace/deployment |
| `dredge k8s response quarantine-namespace` | Apply a deny-all NetworkPolicy across a namespace |
| `dredge k8s response quarantine-pod` | Isolate a pod with a deny-all NetworkPolicy |
| `dredge k8s response revoke-cluster-role-binding` | Delete a ClusterRoleBinding |
| `dredge k8s response revoke-role-binding` | Delete a RoleBinding |
| `dredge k8s response scale-deployment` | Scale a Deployment (default: to 0) |

### Kubernetes — Forensics

| Command | Description |
|---|---|
| `dredge k8s forensics capture-workload-manifest` | Capture a workload controller's manifest |
| `dredge k8s forensics describe-node` | Capture the full manifest of a node |
| `dredge k8s forensics exec-pod-command` | Run a diagnostic command in a pod (best-effort) |
| `dredge k8s forensics get-pod-events` | List Events for a pod |
| `dredge k8s forensics get-pod-logs` | Capture container logs from a pod |
| `dredge k8s forensics get-pod-manifest` | Capture the full manifest of a pod |
| `dredge k8s forensics list-pods-on-node` | List pods scheduled to a node |

### GitHub — Hunt

| Command | Description |
|---|---|
| `dredge github hunt audit` | Hunt GitHub org/enterprise audit logs |
| `dredge github hunt code-scanning` | List code scanning alerts for a repository |
| `dredge github hunt list-deploy-keys` | List deploy keys for a repository |
| `dredge github hunt list-org-members` | List all organization members |
| `dredge github hunt list-outside-collaborators` | List users with repo access outside the org |
| `dredge github hunt secret-scanning` | List secret scanning alerts |

### GitHub — Response

| Command | Description |
|---|---|
| `dredge github response archive-repository` | Archive a repository (make read-only) |
| `dredge github response block-org-member` | Block a user from interacting with the org |
| `dredge github response delete-org-webhook` | Delete an organization-level webhook |
| `dredge github response delete-repo-webhook` | Delete a repository-level webhook |
| `dredge github response remove-org-member` | Remove a user from the organization |
| `dredge github response remove-repo-collaborator` | Remove a collaborator from a repository |
| `dredge github response revoke-deploy-key` | Revoke a repository deploy key |

### GitHub — Forensics

| Command | Description |
|---|---|
| `dredge github forensics branch-protection` | Get branch protection rules |
| `dredge github forensics org-settings` | Capture org configuration snapshot |
| `dredge github forensics org-webhooks` | List all organization webhooks |
| `dredge github forensics repo-collaborators` | List all repository collaborators |
| `dredge github forensics repo-metadata` | Capture repository configuration snapshot |
| `dredge github forensics repo-webhooks` | List all repository webhooks |
