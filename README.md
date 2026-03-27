# Kubernetes Hardening Case Study

This repository contains a comprehensive case study on hardening Kubernetes and cloud-native infrastructure based on proven security practices.

## Overview

This case study demonstrates defense-oriented security approaches for Kubernetes clusters. Starting with a vulnerable Flask application (Phoenix) that has a known Remote Code Execution (RCE) vulnerability, it progressively hardens the infrastructure layer by layer until the vulnerability becomes unexploitable.

**Philosophy**: The vulnerability EXISTS. The code is BROKEN. We don't fix it. But through infrastructure hardening, we significantly reduce the blast radius.

## What we can Learn

- Kubernetes security fundamentals
- Real-world attack patterns and mitigation strategies
- Network policies and admission control
- Container security best practices
- Runtime security monitoring
- Infrastructure as Code (IaC) security scanning

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

## Repository Structure

```
docs/
└── kubernetes-hardening-guide.md    # Comprehensive hardening guide

configs/
├── network-policies/
│   └── deny-metadata.yaml         # Network policy to block cloud metadata
├── kyverno-policies/
│   └── require-non-root.yaml      # Admission policy for non-root containers
└── security-contexts/
    └── hardened-pod.yaml          # Complete hardened pod specification

scripts/
├── attack-simulations/
│   └── kubernetes_attack_simulation.py   # Comprehensive attack simulation across all phases
└── hardening-automation/
    └── apply_hardening.py                # Automation script to apply configurations
```

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
