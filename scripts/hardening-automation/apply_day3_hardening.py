#!/usr/bin/env python3
"""
Advanced Kubernetes Hardening - Day 3 Features
Installs and configures Tetragon runtime security and Istio service mesh.
"""

import subprocess
import sys
import os


def run_command(cmd, description, shell=True):
    """Run a shell command and return boolean success."""
    print(f"Running: {description}")
    try:
        result = subprocess.run(cmd, shell=shell, check=True, capture_output=True, text=True)
        print("✅ Success")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed: {description}")
        print(e.stderr.strip() or e.stdout.strip())
        return False


def create_tetragon_policies():
    """Create Tetragon tracing policies for runtime security."""
    policies_dir = "configs/tetragon-policies"
    os.makedirs(policies_dir, exist_ok=True)

    # Block reverse shells
    reverse_shell_policy = """apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: block-reverse-shells
spec:
  kprobes:
  - call: "security_bprm_check"
    syscall: false
    args:
    - index: 0
      type: "nop"
    - index: 1
      type: "string"
    selectors:
    - matchArgs:
      - index: 1
        operator: "Equal"
        values:
        - "bash"
        - "sh"
        - "zsh"
      matchActions:
      - action: "Signal"
        argSig: 9
    - matchArgs:
      - index: 1
        operator: "Equal"
        values:
        - "nc"
        - "ncat"
        - "netcat"
        - "socat"
      matchActions:
      - action: "Signal"
        argSig: 9
"""

    with open(f"{policies_dir}/block-reverse-shells.yaml", "w") as f:
        f.write(reverse_shell_policy)

    # Block binary execution from /tmp
    binary_execution_policy = """apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: block-binary-execution
spec:
  kprobes:
  - call: "security_bprm_check"
    syscall: false
    args:
    - index: 0
      type: "nop"
    - index: 1
      type: "string"
    selectors:
    - matchArgs:
      - index: 1
        operator: "Prefix"
        values:
        - "/tmp/"
        - "/var/tmp/"
      matchActions:
      - action: "Signal"
        argSig: 9
"""

    with open(f"{policies_dir}/block-binary-execution.yaml", "w") as f:
        f.write(binary_execution_policy)

    # Apply policies
    run_command(f"kubectl apply -f {policies_dir}/", "Apply Tetragon policies")


def configure_istio_sidecar():
    """Configure Istio sidecar injection for mTLS."""
    # Label namespace for sidecar injection
    run_command("kubectl label namespace phoenix istio-injection=enabled --overwrite", "Enable Istio sidecar injection")

    # Create PeerAuthentication for strict mTLS
    peer_auth = """apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
  namespace: phoenix
spec:
  mtls:
    mode: STRICT
"""

    with open("configs/istio-peer-auth.yaml", "w") as f:
        f.write(peer_auth)

    run_command("kubectl apply -f configs/istio-peer-auth.yaml", "Apply Istio PeerAuthentication")

    # Create AuthorizationPolicy
    auth_policy = """apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: phoenix-policy
  namespace: phoenix
spec:
  selector:
    matchLabels:
      app: phoenix
  action: ALLOW
  rules:
  - from:
    - source:
        principals: ["cluster.local/ns/phoenix/sa/phoenix-sa"]
    to:
    - operation:
        methods: ["GET", "POST"]
"""

    with open("configs/istio-auth-policy.yaml", "w") as f:
        f.write(auth_policy)

    run_command("kubectl apply -f configs/istio-auth-policy.yaml", "Apply Istio AuthorizationPolicy")


def setup_grafana_integration():
    """Set up Grafana Cloud integration for observability."""
    print("Grafana Cloud integration setup:")
    print("1. Create a Grafana Cloud account at https://grafana.com/auth/sign-up")
    print("2. Get your API key and endpoint")
    print("3. Configure Prometheus remote write")
    print("4. Set up Loki for logs")
    print("5. Configure Tempo for traces")

    # This would typically involve Helm charts or kubectl apply
    # For now, just provide instructions
    grafana_config = """# Example Prometheus remote write config for values.yaml
remoteWrite:
- url: "https://prometheus-prod-10-prod-us-central-0.grafana.net/api/prom/push"
  basicAuth:
    username: <YOUR_INSTANCE_ID>
    password: <YOUR_API_KEY>
"""

    with open("configs/grafana-integration-example.yaml", "w") as f:
        f.write(grafana_config)

    print("✅ Created Grafana integration example config")


def main():
    print("Advanced Kubernetes Hardening - Day 3")
    print("=" * 50)

    if not run_command("kubectl version --client --short", "Check kubectl"):
        print("kubectl not found. Please install kubectl first.")
        sys.exit(1)

    # Check if Tetragon is installed
    if not run_command("kubectl get deployment -n kube-system tetragon", "Check Tetragon"):
        print("Tetragon not found. Please run the main hardening script first.")
        sys.exit(1)

    # Check if Istio is installed
    if not run_command("istioctl version", "Check Istio"):
        print("Istio not found. Please run the main hardening script first.")
        sys.exit(1)

    # Apply advanced configurations
    create_tetragon_policies()
    configure_istio_sidecar()
    setup_grafana_integration()

    print("\nDay 3 hardening complete!")
    print("Runtime security with Tetragon and service mesh with Istio are now configured.")
    print("Run the attack simulation again to test the advanced controls.")


if __name__ == "__main__":
    main()
