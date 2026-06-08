import os
import subprocess
import sys
from pathlib import Path

# SETTINGS 
FABRIC_PATH = os.getenv(
    "FABRIC_PATH",
    "/home/ruslan/fabric-dev/fabric-samples/test-network",
)
CHAINCODE_PATH = os.getenv(
    "CHAINCODE_PATH",
    str(Path(__file__).resolve().parent / "chaincode"),
)
BOOTSTRAP_USER = os.getenv("BOOTSTRAP_USER", "SecurityService")
BOOTSTRAP_ENROLLMENT_SECRET = os.getenv(
    "BOOTSTRAP_ENROLLMENT_SECRET",
    os.getenv("BOOTSTRAP_PASSWORD", "securitypw"),
)


def run_fabric_command(command: str, timeout: int = 300):
    print(f"\n🚀 Running: {command}")
    try:
        result = subprocess.run(
            command,
            cwd=FABRIC_PATH,
            shell=True,
            text=True,
            capture_output=False,
            timeout=timeout,
        )
        if result.returncode != 0:
            print(f"❌ Command failed: {command}")
            sys.exit(1)
        print("✅ OK")
    except subprocess.TimeoutExpired:
        print(f"❌ Timeout exceeded ({timeout}s): {command}")
        sys.exit(1)
    except Exception as exc:
        print(f"❌ Error: {exc}")
        sys.exit(1)


def run_bash_block(script: str, timeout: int = 300):
    print("\n🚀 Running bootstrap CA registration/enrollment...")
    try:
        result = subprocess.run(
            ["bash", "-lc", script],
            cwd=FABRIC_PATH,
            text=True,
            capture_output=False,
            timeout=timeout,
        )
        if result.returncode != 0:
            print("❌ Bootstrap identity provisioning failed")
            sys.exit(1)
        print("✅ Bootstrap identities are ready")
    except subprocess.TimeoutExpired:
        print(f"❌ Timeout exceeded ({timeout}s) in bootstrap script")
        sys.exit(1)
    except Exception as exc:
        print(f"❌ Error: {exc}")
        sys.exit(1)


def enroll_bootstrap_identities():
    script = rf"""
set -e

export PATH=${{PWD}}/../bin:$PATH
export FABRIC_CFG_PATH=${{PWD}}/../config

echo "== Provision bootstrap identities =="

# -------------------------
# ORG1 service / bootstrap identities
# -------------------------
ORG1_CA_CERT=${{PWD}}/organizations/fabric-ca/org1/tls-cert.pem
export FABRIC_CA_CLIENT_HOME=${{PWD}}/organizations/peerOrganizations/org1.example.com/

# Bootstrap web user: SecurityService
fabric-ca-client register \
  --caname ca-org1 \
  --id.name {BOOTSTRAP_USER} \
  --id.secret {BOOTSTRAP_ENROLLMENT_SECRET} \
  --id.type client \
  --id.maxenrollments -1 \
  --id.attrs 'department=Security Office:ecert,role=SecurityService:ecert' \
  --tls.certfiles ${{ORG1_CA_CERT}} || true

fabric-ca-client enroll \
  -u https://{BOOTSTRAP_USER}:{BOOTSTRAP_ENROLLMENT_SECRET}@localhost:7054 \
  --caname ca-org1 \
  -M ${{PWD}}/organizations/peerOrganizations/org1.example.com/users/{BOOTSTRAP_USER}@org1.example.com/msp \
  --tls.certfiles ${{ORG1_CA_CERT}}

cp ${{PWD}}/organizations/peerOrganizations/org1.example.com/msp/config.yaml \
   ${{PWD}}/organizations/peerOrganizations/org1.example.com/users/{BOOTSTRAP_USER}@org1.example.com/msp/config.yaml

# Internal ML service account
fabric-ca-client register \
  --caname ca-org1 \
  --id.name MLService \
  --id.secret mlservicepw \
  --id.type client \
  --id.maxenrollments -1 \
  --id.attrs 'department=IT Department:ecert,role=MLService:ecert' \
  --tls.certfiles ${{ORG1_CA_CERT}} || true

fabric-ca-client enroll \
  -u https://MLService:mlservicepw@localhost:7054 \
  --caname ca-org1 \
  -M ${{PWD}}/organizations/peerOrganizations/org1.example.com/users/MLService@org1.example.com/msp \
  --tls.certfiles ${{ORG1_CA_CERT}}

cp ${{PWD}}/organizations/peerOrganizations/org1.example.com/msp/config.yaml \
   ${{PWD}}/organizations/peerOrganizations/org1.example.com/users/MLService@org1.example.com/msp/config.yaml

# Optional internal risk service
fabric-ca-client register \
  --caname ca-org1 \
  --id.name RiskService \
  --id.secret riskservicepw \
  --id.type client \
  --id.maxenrollments -1 \
  --id.attrs 'department=Security Office:ecert,role=RiskService:ecert' \
  --tls.certfiles ${{ORG1_CA_CERT}} || true

fabric-ca-client enroll \
  -u https://RiskService:riskservicepw@localhost:7054 \
  --caname ca-org1 \
  -M ${{PWD}}/organizations/peerOrganizations/org1.example.com/users/RiskService@org1.example.com/msp \
  --tls.certfiles ${{ORG1_CA_CERT}}

cp ${{PWD}}/organizations/peerOrganizations/org1.example.com/msp/config.yaml \
   ${{PWD}}/organizations/peerOrganizations/org1.example.com/users/RiskService@org1.example.com/msp/config.yaml

echo "✅ Done: SecurityService, MLService, RiskService"
"""
    run_bash_block(script)


def main():
    print("=" * 52)
    print("🔨 FABRIC INIT (CA + BOOTSTRAP IDENTITIES)")
    print("WARNING: old network state will be removed")
    print("=" * 52)

    run_fabric_command("./network.sh down")
    run_fabric_command("./network.sh up createChannel -ca")
    enroll_bootstrap_identities()

    print("\n🚀 Deploying chaincode...")
    try:
        run_fabric_command(
            f"./network.sh deployCC -ccn securedata -ccp {CHAINCODE_PATH} -ccl go",
            timeout=600,
        )
        print("✅ Chaincode deployed")
    except SystemExit:
        print("⚠️  Chaincode deployment failed")
        print("   Retry manually if Docker was not ready:")
        print(f"   cd {FABRIC_PATH}")
        print(f"   ./network.sh deployCC -ccn securedata -ccp {CHAINCODE_PATH} -ccl go")

    print("\n" + "=" * 52)
    print("🎉 Network is ready")
    print(f"Bootstrap enrollment secret is configured for {BOOTSTRAP_USER} (used only for bootstrap invite activation).")
    print("Next step: start SecurityService + MLService agents, backend, static site")
    print("Then open the UI on http://localhost:8000/, activate the SecurityService device with WebAuthn/passkey, and issue invite tickets for other users.")
    print("=" * 52)


if __name__ == "__main__":
    main()
