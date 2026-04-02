#!/usr/bin/env python3
"""
Kubernetes Hardening Automation Script
Applies security best practices to a cluster.
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

def ensure_namespace(namespace):
    """Create or update a namespace."""
    run_command(
        f"kubectl create namespace {namespace} --dry-run=client -o yaml | kubectl apply -f -",
        f"Ensure namespace {namespace}"
    )


def is_kyverno_installed():
    """Return True if Kyverno is already installed."""
    return run_command("kubectl get deployment -n kyverno kyverno", "Check Kyverno deployment")


def install_kyverno():
    """Install Kyverno if not present."""
    if is_kyverno_installed():
        print("Kyverno is already installed.")
        return

    print("Kyverno is not installed. Installing Kyverno...")
    run_command(
        "kubectl apply -f https://github.com/kyverno/kyverno/releases/latest/download/install.yaml",
        "Install Kyverno"
    )


def apply_network_policies():
    """Apply network policies"""
    policies = [
        "configs/network-policies/deny-metadata.yaml",
        "configs/network-policies/deny-unexpected-ingress.yaml"
    ]
    for policy in policies:
        if os.path.exists(policy):
            run_command(f"kubectl apply -f {policy}", f"Apply {policy}")
        else:
            print(f"⚠️  Policy not found: {policy}")

def apply_kyverno_policies():
    """Apply Kyverno policies"""
    policies = [
        "configs/kyverno-policies/require-non-root.yaml"
    ]
    for policy in policies:
        if os.path.exists(policy):
            run_command(f"kubectl apply -f {policy}", f"Apply {policy}")

def install_kubescape():
    """Install Kubescape if not present."""
    if run_command("kubescape version", "Check Kubescape"):
        print("Kubescape is already installed.")
        return

    print("Installing Kubescape...")
    run_command(
        "curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | /bin/bash",
        "Install Kubescape"
    )


def install_checkov():
    """Install Checkov if not present."""
    if run_command("checkov --version", "Check Checkov"):
        print("Checkov is already installed.")
        return

    print("Installing Checkov...")
    run_command("pip install checkov", "Install Checkov")


def install_cosign():
    """Install Cosign if not present."""
    if run_command("cosign version", "Check Cosign"):
        print("Cosign is already installed.")
        return

    print("Installing Cosign...")
    run_command(
        "curl -O -L 'https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64' && "
        "chmod +x cosign-linux-amd64 && sudo mv cosign-linux-amd64 /usr/local/bin/cosign",
        "Install Cosign"
    )


def install_tetragon():
    """Install Tetragon for runtime security."""
    if run_command("kubectl get deployment -n kube-system tetragon", "Check Tetragon"):
        print("Tetragon is already installed.")
        return

    print("Installing Tetragon...")
    run_command(
        "helm repo add cilium https://helm.cilium.io/ && helm repo update",
        "Add Cilium Helm repo"
    )
    run_command(
        "helm install tetragon cilium/tetragon -n kube-system",
        "Install Tetragon via Helm"
    )


def install_istio():
    """Install Istio service mesh."""
    if run_command("istioctl version", "Check Istio"):
        print("Istio is already installed.")
        return

    print("Installing Istio...")
    run_command(
        "curl -L https://istio.io/downloadIstio | sh - && "
        "export PATH=$PWD/istio-*/bin:$PATH && "
        "istioctl install --set profile=default -y",
        "Install Istio"
    )


def run_security_scans():
    """Run security scans with Kubescape and Checkov."""
    print("Running security scans...")
    run_command("kubescape scan", "Run Kubescape cluster scan")
    run_command("checkov -f configs/ --framework kubernetes", "Run Checkov on configs")


def apply_hardened_pod_spec():
    """Apply hardened pod specification."""
    hardened_yaml = """apiVersion: apps/v1
kind: Deployment
metadata:
  name: phoenix-hardened
  namespace: phoenix
spec:
  replicas: 1
  selector:
    matchLabels:
      app: phoenix-hardened
  template:
    metadata:
      labels:
        app: phoenix-hardened
    spec:
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
      containers:
      - name: phoenix
        image: phoenix:v1
        ports:
        - containerPort: 8080
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          runAsNonRoot: true
          runAsUser: 1000
          capabilities:
            drop:
            - ALL
        volumeMounts:
        - name: tmp
          mountPath: /tmp
        - name: cache
          mountPath: /home/app/.cache
      volumes:
      - name: tmp
        emptyDir: {}
      - name: cache
        emptyDir: {}
"""
    with open("configs/security-contexts/hardened-pod.yaml", "w") as f:
        f.write(hardened_yaml)
    run_command("kubectl apply -f configs/security-contexts/hardened-pod.yaml", "Apply hardened pod spec")
    print("Kubernetes Hardening Automation")
    print("=" * 40)

    # Check if kubectl is available
    if not run_command("kubectl version --client", "Check kubectl"):
        print("kubectl not found. Please install kubectl first.")
        sys.exit(1)

    # Install security tools
    install_kubescape()
    install_checkov()
    install_cosign()
    install_tetragon()
    install_istio()

    # Apply configurations
    ensure_namespace("phoenix")
    install_kyverno()
    apply_network_policies()
    apply_kyverno_policies()
    enable_pod_security_standards(["default", "phoenix"])
    apply_hardened_pod_spec()

    # Run scans
    run_security_scans()

    print("\nHardening automation complete!")
    print("Review the applied configurations and test with attack scripts.")

if __name__ == "__main__":
    main()