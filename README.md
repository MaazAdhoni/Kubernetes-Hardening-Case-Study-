# Hardening Kubernetes & Cloud-Native Infrastructure

Welcome to Hardening Kubernetes & Cloud-Native Infrastructure - a comprehensive case study and hands-on guide.

## Introduction

This repository contains a complete case study on hardening Kubernetes and cloud-native infrastructure, based on proven security practices from real-world deployments. Starting with a vulnerable Flask application (Phoenix) that has a known Remote Code Execution (RCE) vulnerability, it progressively hardens the infrastructure layer by layer until the vulnerability becomes unexploitable.

## Philosophy

This is a defense-focused approach. You won't become a red teamer. You'll learn to defend.

We start with Phoenix - a Flask app with an RCE vulnerability in a debug endpoint. We're not fixing the code. Instead, we'll progressively harden the infrastructure until the vulnerability becomes unexploitable.

**"The vulnerability EXISTS. The code is BROKEN. We don't fix it. But through infrastructure hardening, we significantly reduce the blast radius."**

## What You'll Get

- Comprehensive understanding of Kubernetes security fundamentals
- Real-world attack patterns and mitigation strategies
- Hands-on implementation of defense-in-depth controls
- Automated hardening scripts and configurations
- Integration with industry-standard security tools
- Complete case study with vulnerable app and hardening progression

## Vulnerable Application (Phoenix)

The Phoenix application is located in the `phoenix/` directory:
- `app.py`: Flask application with deliberate RCE vulnerability in `/execute` endpoint
- `Dockerfile`: Container build configuration
- `requirements.txt`: Python dependencies

**Security Note**: This application contains intentional vulnerabilities for educational purposes only. Do not deploy in production environments.

## Prerequisites

- Basic Kubernetes knowledge (pods, deployments, services, namespaces)
- Familiarity with kubectl commands
- Comfort with command line operations
- Access to a Kubernetes cluster (local or managed)

## Lab Environment

### SDLC Pipeline
- **Developer**: git push
- **Git Platform**: Detects changes, triggers build
- **GitOps Tool**: Applies manifests to cluster
- **Container Registry**: Pulls images from registry

### Kubernetes Environment
Each setup includes:
- **Phoenix** (web namespace): Vulnerable Flask app with RCE, privileged container, hostPID, hostNetwork, host filesystem mounted
- **Payment API** (payments namespace): Internal API with customer data, hardened (non-root, read-only fs)
- **Checkout** (payments namespace): Calls payment-api, hardened (non-root, read-only fs)

### Tools to Install
| Tool | Version | Install |
|------|---------|---------|
| kubectl | 1.34.x | [kubernetes.io/docs/tasks/tools](https://kubernetes.io/docs/tasks/tools) |
| Helm | latest | [helm.sh/docs/intro/install](https://helm.sh/docs/intro/install) |
| Docker | latest | [docs.docker.com/get-started/get-docker](https://docs.docker.com/get-started/get-docker) |
| Git | latest | [git-scm.com/book/en/v2/Getting-Started-Installing](https://git-scm.com/book/en/v2/Getting-Started-Installing) |

### Verification
```bash
kubectl version --client   # Should show 1.34.x
helm version
docker --version
git --version
```

## Phase 1: Perimeter Defenses

### Kubernetes Security Primer

#### Cluster Architecture
Every Kubernetes cluster has two main parts:
- **Control Plane**: API Server, etcd, Scheduler, Controller Manager
- **Worker Nodes**: kubelet, Container Runtime, kube-proxy

#### API Request Flow
Every request goes through: Authentication → Authorization → Admission Control → etcd

#### Key Components
- **Namespaces**: Logical grouping (not security boundaries)
- **Pods & Containers**: Shared network/storage, security contexts
- **Service Accounts**: Identity for pods, auto-mounted tokens
- **Secrets**: Base64 encoded (not encrypted by default)
- **RBAC**: Role-Based Access Control for permissions
- **NetworkPolicy**: Pod-level firewall (not enabled by default)
- **Admission Control**: Gatekeepers for request validation

#### What Attackers Want
- Service Account tokens
- Cloud metadata (AWS/GCP/Azure credentials)
- Secrets and API keys
- Lateral movement via pod network
- Host filesystem access

#### Real-World Attacks
- **Tesla Cryptojacking (2018)**: Exposed Dashboard → admin access → cryptomining
- **Hildegard/TeamTNT (2021)**: Anonymous kubelet → reverse shell → cryptomining
- **Siloscape (2021)**: Windows container escape → host access
- **SCARLETEEL (2023)**: JupyterLab + IAM → cryptomining
- **Dero Cryptojacking (2023)**: Anonymous API access → cryptomining

#### Threat Frameworks
- **MITRE ATT&CK for Containers**: Tactics and techniques
- **Microsoft Threat Matrix for Kubernetes**: Practical mitigations
- **D3FEND**: Defensive countermeasures

### Implementation
- **Network Policies**: Block metadata access, restrict egress
- **RBAC Hardening**: Least privilege for service accounts
- **Attack Simulation**: Test defenses against real attacks

## Phase 2: Container Hardening

### Service Account Tokens
- **Extended Expiration**: 1-year tokens by default
- **Short-Lived Tokens**: 10-minute expiration for better security

### Dangerous Pod Permissions
Remove these to prevent container escape:
- `hostNetwork: true`
- `hostPID: true`
- `hostIPC: true`
- `hostPath` volumes

### Security Context
- `runAsNonRoot: true`
- `runAsUser: 1000`
- `readOnlyRootFilesystem: true`
- `allowPrivilegeEscalation: false`
- `capabilities: {drop: ["ALL"]}`
- `seccompProfile: {type: "RuntimeDefault"}`

### Pod Security Standards
Three levels: Privileged, Baseline, Restricted

### Container Image Security
- **Scanning**: Kubescape, Checkov, Trivy for vulnerabilities
- **Signing**: Cosign for image integrity verification
- **IaC Scanning**: Static analysis of manifests

### Implementation
- **Pod Hardening**: Security contexts, PSS enforcement
- **Image Pipeline**: Scanning and signing in CI/CD
- **Manifest Validation**: IaC security checks

## Phase 3: Advanced Runtime Controls

### Admission Controllers
- **Built-in**: PodSecurity, ServiceAccount, etc.
- **Dynamic**: Kyverno, OPA/Gatekeeper for custom policies

### Runtime Security with Tetragon
- **eBPF-based monitoring**: Process execution, file access, network connections
- **Enforcement**: Block reverse shells, unauthorized binaries
- **TracingPolicies**: Define what to monitor and respond to

### Service Mesh with Istio
- **mTLS**: Encrypt pod-to-pod traffic
- **AuthorizationPolicy**: Control access between services
- **Ambient Mode**: Node-level encryption without sidecars

### Monitoring & Observability
- **Grafana Cloud**: Centralized logging and metrics
- **Tetragon Events**: Security event streaming
- **Policy Reports**: Kyverno compliance monitoring

### Implementation
- **Kyverno Policies**: Enforce image registries, non-root users
- **Tetragon Policies**: Block malicious activity
- **Istio Configuration**: mTLS and authorization
- **Grafana Integration**: Event visualization

## Repository Structure

```
docs/
└── kubernetes-hardening-guide.md    # Detailed hardening guide

configs/
├── deployments/
│   └── phoenix-deployment.yaml        # Vulnerable Phoenix app
├── network-policies/
│   ├── deny-metadata.yaml             # Block cloud metadata
│   └── deny-unexpected-ingress.yaml   # Ingress restrictions
├── namespaces/
│   └── phoenix-namespace.yaml         # Namespace manifests
├── services/
│   └── phoenix-service.yaml           # Service definitions
├── kyverno-policies/
│   └── require-non-root.yaml          # Admission policies
└── security-contexts/
    └── hardened-pod.yaml             # Hardened pod specs

phoenix/
├── app.py                            # Vulnerable Flask app
├── Dockerfile                        # Container build
└── requirements.txt                  # Python dependencies

scripts/
├── attack-simulations/
│   └── kubernetes_attack_simulation.py   # Attack testing across phases
└── hardening-automation/
    ├── apply_hardening.py                # Core hardening automation
    └── apply_day3_hardening.py           # Advanced controls
```

## Tools Reference

### Defensive Tools
- **Kubescape**: CIS, NSA, MITRE scanning
- **Checkov**: IaC scanning and validation
- **Kyverno**: Kubernetes-native policy engine
- **Tetragon**: eBPF runtime security
- **Istio**: Service mesh with mTLS
- **Cosign**: Container image signing

### Offensive Tools (for Testing)
- **Peirates**: Kubernetes pentest toolkit
- **CDK**: Container escape toolkit
- **kube-hunter**: Cluster vulnerability scanning

## kubectl Commands Quick Reference

### Cluster Overview
```bash
kubectl cluster-info
kubectl get nodes -o wide
kubectl get namespaces
```

### Pod Investigation
```bash
kubectl get pods -A -o wide
kubectl describe pod <pod-name>
kubectl logs <pod-name>
kubectl exec -it <pod-name> -- /bin/sh
```

### Security Checks
```bash
kubectl get networkpolicies -A
kubectl get validatingwebhookconfigurations
kubectl auth can-i --list --as=system:serviceaccount:<ns>:<sa>
```

## Cheatsheet

### Kubescape
```bash
kubescape scan                    # Full cluster scan
kubescape scan framework nsa      # NSA framework
kubescape scan control C-0034 -v  # Specific control
```

### Kyverno
```bash
kubectl get clusterpolicy
kubectl describe clusterpolicy <name>
```

### Tetragon
```bash
kubectl get tracingpolicies
kubectl logs -n kube-system ds/tetragon -c export-stdout
```

### Istio
```bash
kubectl get peerauthentication -A
kubectl get authorizationpolicy -A
```

## Key Takeaways

1. **Defense in Depth**: Multiple overlapping security controls
2. **Least Privilege**: Minimal permissions at every layer
3. **Zero Trust**: Verify all access and communications
4. **Automation**: Policy-as-code for consistent enforcement
5. **Monitoring**: Continuous visibility and rapid response
6. **Immutable Infrastructure**: Signed images, read-only filesystems
7. **Runtime Protection**: eBPF-based detection and blocking

## CEO's Approach to Security

From an executive perspective, Kubernetes hardening requires:
- **Risk Assessment**: Identify crown jewel assets and attack surfaces
- **Compliance Alignment**: Map controls to frameworks (CIS, NIST, MITRE)
- **Cost-Benefit Analysis**: Balance security with operational efficiency
- **Metrics and KPIs**: Measure security posture and incident response times
- **Cultural Change**: Foster security-first development practices
- **Continuous Improvement**: Regular audits and updates based on threat intelligence

This case study provides the technical foundation for implementing enterprise-grade Kubernetes security.

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
3. Build and deploy the Phoenix vulnerable app
4. Apply configurations from `configs/`
5. Run attack simulations from `scripts/`

## Quick start

```powershell
cd kubernetes-hardening-case-study\phoenix
docker build -t phoenix:v1 .
cd ..
kubectl apply -f configs/namespaces/phoenix-namespace.yaml
kubectl apply -f configs/deployments/phoenix-deployment.yaml
kubectl apply -f configs/services/phoenix-service.yaml
```

If you use `kind` or `minikube`, load the local image into your cluster before applying the deployment.

To apply hardening:

```powershell
python scripts/hardening-automation/apply_hardening.py
```

To run the simulation:

```powershell
python scripts/attack-simulations/kubernetes_attack_simulation.py --target http://phoenix.default.svc.cluster.local --all
```

## Contributing

This case study is based on practical security research and implementation. For questions or improvements, please refer to the security documentation and best practices.

## License

This repository is licensed under the MIT License. See `LICENSE` for details.