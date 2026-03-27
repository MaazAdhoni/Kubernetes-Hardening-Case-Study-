#!/usr/bin/env python3
"""
Kubernetes Hardening Automation Script
Applies security best practices to a cluster.
"""

import subprocess
import sys
import os

def run_command(cmd, description):
    """Run a shell command and return success"""
    print(f"Running: {description}")
    try:
        result = subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
        print("✅ Success")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed: {e}")
        return False

def apply_network_policies():
    """Apply network policies"""
    policies = [
        "configs/network-policies/deny-metadata.yaml"
    ]
    for policy in policies:
        if os.path.exists(policy):
            run_command(f"kubectl apply -f {policy}", f"Apply {policy}")

def apply_kyverno_policies():
    """Apply Kyverno policies"""
    policies = [
        "configs/kyverno-policies/require-non-root.yaml"
    ]
    for policy in policies:
        if os.path.exists(policy):
            run_command(f"kubectl apply -f {policy}", f"Apply {policy}")

def enable_pod_security_standards():
    """Enable Pod Security Standards"""
    run_command("kubectl label namespace default pod-security.kubernetes.io/enforce=restricted", "Enable PSS Restricted")

def main():
    print("Kubernetes Hardening Automation")
    print("=" * 40)

    # Check if kubectl is available
    if not run_command("kubectl version --client", "Check kubectl"):
        print("kubectl not found. Please install kubectl first.")
        sys.exit(1)

    # Apply configurations
    apply_network_policies()
    apply_kyverno_policies()
    enable_pod_security_standards()

    print("\nHardening automation complete!")
    print("Review the applied configurations and test with attack scripts.")

if __name__ == "__main__":
    main()