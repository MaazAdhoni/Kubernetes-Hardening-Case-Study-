# Comprehensive Kubernetes Hardening Case Study

## Overview

This comprehensive guide covers end-to-end Kubernetes cluster hardening based on proven security practices. It demonstrates defense-oriented security approaches, starting with a vulnerable Flask application (Phoenix) that has a known Remote Code Execution (RCE) vulnerability, and progressively hardening the infrastructure layer by layer until the vulnerability becomes unexploitable.

**Philosophy**: The vulnerability EXISTS. The code is BROKEN. We don't fix it. But through infrastructure hardening, we significantly reduce the blast radius.

## Implementation Phases

### Phase 1: Perimeter Defenses
- Kubernetes architecture and API flow
- Service accounts and RBAC
- Network policies
- Cloud metadata access
- Attack simulation and initial defenses

### Phase 2: Container Hardening
- Pod security standards
- Container security contexts
- Image scanning and signing
- IaC security validation
- Advanced hardening techniques

### Phase 3: Advanced Controls
- Admission controllers (Kyverno)
- Runtime security with eBPF (Tetragon)
- Image signature verification
- Automated policy enforcement

## Prerequisites

- Basic Kubernetes knowledge (pods, deployments, services)
- Familiarity with kubectl commands
- Command-line comfort
- Access to a Kubernetes cluster

## Tools Covered

- kubectl
- Helm
- Docker
- Git
- Kubescape (security scanning)
- Kyverno (policy engine)
- Tetragon (runtime security)
- Cosign (image signing)

## Key Takeaways

1. **Defense in Depth**: Multiple layers of security controls
2. **Least Privilege**: Minimal permissions and access
3. **Zero Trust**: Verify everything, trust nothing
4. **Automation**: Policy-as-code for consistent security
5. **Monitoring**: Runtime detection and response

## Real-World Impact

This hardening approach has been validated against real attack patterns from:
- Tesla Cryptojacking (2018)
- TeamTNT/Hildegard (2021)
- Siloscape (2021)
- SCARLETEEL (2023)
- Dero Cryptojacking (2023)

## Getting Started

1. Set up your Kubernetes environment
2. Review the documentation in `docs/`
3. Apply configurations from `configs/`
4. Run attack simulations from `scripts/`

## Contributing

This case study is based on practical security research and implementation. For questions or improvements, please refer to the security documentation and best practices.

## License

Case study materials for professional use.

---

## Phase 1: Perimeter Defenses

### Welcome to Phase 1

Today we begin our journey into understanding how attackers exploit Kubernetes clusters and how defenders can respond.

### Kubernetes Security Primer

#### Cluster Architecture

Every Kubernetes cluster has two main parts:

- **Control Plane**: The brain. Makes decisions, stores state in etcd.
- **Worker Nodes**: Where your workloads run.

#### API Request Flow

Every request to Kubernetes goes through authentication and authorization. Admission control only runs for mutating requests (create, update, delete).

#### Namespaces

Logical grouping of resources. Not a security boundary by default.

#### Pods and Containers

A Pod is one or more containers sharing network and storage.

#### Security Context

Controls how containers run.

#### Service Accounts

Every pod gets an identity. This identity is a Service Account.

#### Secrets

Kubernetes stores sensitive data as Secrets. They're base64 encoded, not encrypted by default.

#### RBAC

Role-Based Access Control. Defines who can do what on which resources.

#### NetworkPolicy

Pod-level firewall. Not enabled by default - all pods can talk to all pods.

#### Admission Control

Gatekeepers that intercept requests before they hit etcd.

### Pod Security Standards

Three security levels for pods:

- **Privileged**: Everything allowed
- **Baseline**: Blocks known privilege escalations
- **Restricted**: Fully hardened

### What Attackers Want

- Service Account Token
- Cloud Metadata
- Secrets
- API Access
- Lateral Movement

### Default Kubernetes = Dangerous

Out of the box, your cluster has:

- All pods can talk to all pods
- All pods can reach cloud metadata
- SA token auto-mounted
- No admission control
- Containers run as root
- No network isolation

### Real-World Kubernetes Attacks

#### Tesla Cryptojacking (2018)
- Entry point: Kubernetes Dashboard exposed
- Fix: Auth on admin interfaces

#### TeamTNT/Hildegard (2021)
- Entry point: Anonymous kubelet access
- Fix: Disable anonymous auth

#### Siloscape (2021)
- Entry point: Windows container escape
- Fix: Hyper-V isolation

#### SCARLETEEL (2023)
- Entry point: JupyterLab + IAM misconfig
- Fix: Least privilege IAM

#### Dero Cryptojacking (2023)
- Entry point: Anonymous API access
- Fix: RBAC + admission control

### Know Your Enemy

#### MITRE ATT&CK for Containers

Industry standard for mapping adversary tactics and techniques.

#### Microsoft Threat Matrix for Kubernetes

Maps techniques to Kubernetes-specific mitigations.

### Threat Modeling

Four questions:
1. What are we working on?
2. What can go wrong?
3. What are we going to do about it?
4. Did we do a good job?

### Labs

#### Explore Your Cluster
- Cluster info and node IPs
- Exposed services
- Control plane visibility
- Gitea and Harbor exploration

#### Kubescape Scanning
Scan cluster against security frameworks.

#### Network Policy Implementation
Block metadata and C2 servers.

#### RBAC Hardening
Restrict Phoenix service account permissions.

#### Phase 1 Attack Simulation
Run attack scripts to validate defenses.

### Key Defenses Applied

1. **Network Policies**: Block metadata and C2 egress
2. **RBAC**: Least privilege for service accounts
3. **Pod Security Standards**: Baseline enforcement
4. **Admission Control**: Basic validation

### Phase 1 Summary

By the end of Phase 1, we've established perimeter defenses that block the most common initial access vectors. The cluster is no longer trivially exploitable, but the containers themselves remain vulnerable.

---

## Phase 2: Container Hardening

### Welcome to Phase 2

Two phases of defenses are in place. Today we block container escape.

### Hardening Service Account Tokens

#### Extended Token Expiration
Default projected token has 1-year expiry.

#### Short-Lived Tokens
Set expirationSeconds to 600 (10 minutes) for better security.

### Dangerous Pod Permissions

Four pod spec fields break container isolation:

- `hostNetwork: true`
- `hostPID: true`
- `hostIPC: true`
- `hostPath` volumes

### Pod Security Standards

#### Three Levels
- **Privileged**: No restrictions
- **Baseline**: Blocks obvious dangers
- **Restricted**: Fully hardened

#### Enforcement Modes
- `enforce`: Rejects violations
- `warn`: Shows warnings
- `audit`: Logs violations

### Security Context

#### Hardening Options
- `runAsNonRoot: true`
- `runAsUser: 1000`
- `readOnlyRootFilesystem: true`
- `allowPrivilegeEscalation: false`
- `capabilities: {drop: ["ALL"]}`
- `seccompProfile: {type: RuntimeDefault}`

#### Complete Hardened Context
Pod-level and container-level settings for maximum security.

### Read-Only Root Filesystem

Makes container filesystem read-only. Prevents persistence.

### Default Container User

Containers run as root by default. Enforce non-root with `runAsNonRoot: true`.

### Container Image Scanning

#### Tools
- **Kubescape**: Grype-based scanning
- **Trivy**: Comprehensive scanning
- **Checkov**: IaC + image scanning

#### What It Finds
- OS package vulnerabilities
- Language dependencies
- Base image bloat

### IaC Security Scanning

#### Tools
- **Checkov**: Python-based, 1000+ checks
- **KICS**: Go-based, Rego queries
- **Kubescape**: Kubernetes-focused

#### Frameworks Supported
- Kubernetes manifests
- Dockerfiles
- Terraform
- CloudFormation

### Container Image Signing

#### Cosign
Signs and verifies OCI container images.

#### Modes
- **Key Pair**: Generate and manage keys
- **Keyless**: OIDC-based identity

#### Verification
Enforce signed images at admission time.

### Labs

#### Short-Lived Tokens
Configure 10-minute token expiry.

#### Remove Dangerous Permissions
Eliminate hostNetwork, hostPID, privileged, hostPath.

#### Pod Security Standards
Enforce Restricted level.

#### Read-Only Filesystem
Enable readOnlyRootFilesystem with writable emptyDir mounts.

#### Non-Root User
Set runAsNonRoot and specific UID.

#### Image Scanning
Scan Phoenix and Payment API images.

#### IaC Scanning
Validate manifests with Checkov/Kubescape.

#### Image Signing
Sign images with Cosign.

#### Gitea Actions Integration
Automate scanning and signing in CI/CD.

### Key Defenses Applied

1. **Pod Security Standards**: Restricted enforcement
2. **Security Context**: Complete hardening
3. **Image Security**: Scanning and signing
4. **IaC Security**: Automated validation
5. **Token Security**: Short-lived tokens

### Phase 2 Summary

By the end of Phase 2, containers are hardened against escape. Images are scanned and signed. Infrastructure as Code is validated. The attack surface is dramatically reduced.

---

## Phase 3: Advanced Controls

### Welcome to Phase 3

Two phases of defenses are in place. Today we complete our detection journey.

### Admission Controllers

#### Built-in Controllers
- **PodSecurity**: Enforces PSS
- **NodeRestriction**: Limits kubelet access
- **LimitRanger**: Applies resource defaults
- **ServiceAccount**: Auto-mounts tokens

#### Dynamic Admission Control
Webhook-based controllers for custom policies.

### Policy Engines

#### OPA/Gatekeeper
- Policy language: Rego
- General-purpose policy engine
- ConstraintTemplates + Constraints

#### Kyverno
- Policy language: YAML
- Kubernetes-native
- ClusterPolicy resources

### Kyverno Policies

#### Rule Types
- **Validate**: Accept/reject resources
- **Mutate**: Modify resources
- **Generate**: Create additional resources
- **VerifyImages**: Check signatures

#### Policy Structure
- `validationFailureAction`: Enforce/Audit
- `match`: Resource selection
- `validate.pattern`: Expected structure

### Runtime Security

#### eBPF
Runs programs inside the Linux kernel to monitor events.

#### Tetragon
eBPF-based runtime security for Kubernetes.

#### What It Monitors
- Process execution
- File access
- Network connections

### Labs

#### Kyverno Installation
Install Kyverno admission controller.

#### Registry Restrictions
Only allow images from approved registries.

#### Non-Root Enforcement
Require all containers to run as non-root.

#### Image Signature Verification
Reject unsigned images at admission.

#### Runtime Monitoring
Deploy Tetragon for process and network monitoring.

### Key Defenses Applied

1. **Admission Control**: Kyverno policies
2. **Image Verification**: Signature enforcement
3. **Runtime Security**: eBPF monitoring
4. **Automated Enforcement**: Policy-as-code

### Phase 3 Summary

By the end of Phase 3, we have complete visibility and control. Admission controllers prevent misconfigurations. Runtime security detects and responds to threats. The cluster is hardened end-to-end.

## Complete Security Posture

### Defense Layers
1. **Network**: Policies block unauthorized traffic
2. **Identity**: RBAC limits permissions
3. **Admission**: Policies prevent bad deployments
4. **Container**: Security contexts prevent escape
5. **Runtime**: eBPF monitors execution
6. **Images**: Scanning and signing ensure integrity

### Automation
- CI/CD integration for scanning
- Policy enforcement at admission
- Runtime alerting and response

### Monitoring
- Audit logs for API access
- Runtime events from Tetragon
- Policy violations from Kyverno

## Real-World Validation

This hardening approach addresses all major attack vectors:
- Exposed services → Network policies
- Anonymous access → RBAC
- Container escape → Security contexts
- Vulnerable images → Scanning/signing
- Runtime threats → eBPF monitoring

## Conclusion

Through systematic hardening, we've transformed a vulnerable cluster into a secure, production-ready environment. The same principles apply to any Kubernetes deployment, whether self-managed or cloud-hosted.