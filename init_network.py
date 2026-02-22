import subprocess
import sys

# --- НАСТРОЙКИ ---
FABRIC_PATH = "/home/ruslan/fabric-dev/fabric-samples/test-network"

def run_fabric_command(command: str, timeout: int = 300):
    """Run a fabric command with output capture and timeout handling"""
    print(f"\n🚀 Выполняю: {command}")
    try:
        result = subprocess.run(
            command,
            cwd=FABRIC_PATH,
            shell=True,
            text=True,
            capture_output=False,
            timeout=timeout
        )
        if result.returncode != 0:
            print(f"❌ Ошибка при выполнении: {command}")
            sys.exit(1)
        print("✅ Успешно!")
    except subprocess.TimeoutExpired:
        print(f"❌ Timeout превышен ({timeout}s): {command}")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Ошибка: {e}")
        sys.exit(1)

def run_bash_block(script: str, timeout: int = 300):
    """Run bash script with output capture and error handling"""
    print("\n🚀 Выполняю bash-блок (register/enroll users with attrs)...")
    try:
        result = subprocess.run(
            ["bash", "-lc", script],
            cwd=FABRIC_PATH,
            text=True,
            capture_output=False,
            timeout=timeout
        )
        if result.returncode != 0:
            print("❌ Ошибка в bash-блоке регистрации/энролла пользователей")
            sys.exit(1)
        print("✅ Пользователи созданы/обновлены!")
    except subprocess.TimeoutExpired:
        print(f"❌ Timeout превышен ({timeout}s) в bash-блоке")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Ошибка: {e}")
        sys.exit(1)

def enroll_custom_identities():
    # ⚠️ Порты CA в test-network (обычно такие):
    # Org1 CA: 7054, Org2 CA: 8054
    script = r"""
set -e

export PATH=${PWD}/../bin:$PATH
export FABRIC_CFG_PATH=${PWD}/../config

echo "== Enroll custom users with attributes =="

# -------------------------
# ORG1: Ruslan + SecurityService
# -------------------------
ORG1_CA_CERT=${PWD}/organizations/fabric-ca/org1/tls-cert.pem
export FABRIC_CA_CLIENT_HOME=${PWD}/organizations/peerOrganizations/org1.example.com/

# Ruslan (Researcher / IT Department)
fabric-ca-client register \
  --caname ca-org1 \
  --id.name Ruslan \
  --id.secret ruslanpw \
  --id.type client \
  --id.attrs 'department=IT Department:ecert,role=Researcher:ecert' \
  --tls.certfiles ${ORG1_CA_CERT} || true

fabric-ca-client enroll \
  -u https://Ruslan:ruslanpw@localhost:7054 \
  --caname ca-org1 \
  -M ${PWD}/organizations/peerOrganizations/org1.example.com/users/Ruslan@org1.example.com/msp \
  --tls.certfiles ${ORG1_CA_CERT}

cp ${PWD}/organizations/peerOrganizations/org1.example.com/msp/config.yaml \
   ${PWD}/organizations/peerOrganizations/org1.example.com/users/Ruslan@org1.example.com/msp/config.yaml

# SecurityService (для блокировок)
fabric-ca-client register \
  --caname ca-org1 \
  --id.name SecurityService \
  --id.secret securitypw \
  --id.type client \
  --id.attrs 'department=Security Office:ecert,role=SecurityService:ecert' \
  --tls.certfiles ${ORG1_CA_CERT} || true

fabric-ca-client enroll \
  -u https://SecurityService:securitypw@localhost:7054 \
  --caname ca-org1 \
  -M ${PWD}/organizations/peerOrganizations/org1.example.com/users/SecurityService@org1.example.com/msp \
  --tls.certfiles ${ORG1_CA_CERT}

cp ${PWD}/organizations/peerOrganizations/org1.example.com/msp/config.yaml \
   ${PWD}/organizations/peerOrganizations/org1.example.com/users/SecurityService@org1.example.com/msp/config.yaml


# RiskService (risk engine that can auto-block via BlockUserForSeconds)
fabric-ca-client register \
  --caname ca-org1 \
  --id.name RiskService \
  --id.secret riskservicepw \
  --id.type client \
  --id.attrs 'department=Security Office:ecert,role=RiskService:ecert' \
  --tls.certfiles ${ORG1_CA_CERT} || true

fabric-ca-client enroll \
  -u https://RiskService:riskservicepw@localhost:7054 \
  --caname ca-org1 \
  -M ${PWD}/organizations/peerOrganizations/org1.example.com/users/RiskService@org1.example.com/msp \
  --tls.certfiles ${ORG1_CA_CERT}

cp ${PWD}/organizations/peerOrganizations/org1.example.com/msp/config.yaml \
   ${PWD}/organizations/peerOrganizations/org1.example.com/users/RiskService@org1.example.com/msp/config.yaml




# MLService (сервисная учётка для записи AI подсказок в chaincode)
fabric-ca-client register \
  --caname ca-org1 \
  --id.name MLService \
  --id.secret mlservicepw \
  --id.type client \
  --id.attrs 'department=IT Department:ecert,role=MLService:ecert' \
  --tls.certfiles ${ORG1_CA_CERT} || true

fabric-ca-client enroll \
  -u https://MLService:mlservicepw@localhost:7054 \
  --caname ca-org1 \
  -M ${PWD}/organizations/peerOrganizations/org1.example.com/users/MLService@org1.example.com/msp \
  --tls.certfiles ${ORG1_CA_CERT}

cp ${PWD}/organizations/peerOrganizations/org1.example.com/msp/config.yaml \
   ${PWD}/organizations/peerOrganizations/org1.example.com/users/MLService@org1.example.com/msp/config.yaml


# -------------------------
# ORG2: Ersultan
# -------------------------
ORG2_CA_CERT=${PWD}/organizations/fabric-ca/org2/tls-cert.pem
export FABRIC_CA_CLIENT_HOME=${PWD}/organizations/peerOrganizations/org2.example.com/

fabric-ca-client register \
  --caname ca-org2 \
  --id.name Ersultan \
  --id.secret ersultanpw \
  --id.type client \
  --id.attrs 'department=Physics Center:ecert,role=Researcher:ecert' \
  --tls.certfiles ${ORG2_CA_CERT} || true

fabric-ca-client enroll \
  -u https://Ersultan:ersultanpw@localhost:8054 \
  --caname ca-org2 \
  -M ${PWD}/organizations/peerOrganizations/org2.example.com/users/Ersultan@org2.example.com/msp \
  --tls.certfiles ${ORG2_CA_CERT}

cp ${PWD}/organizations/peerOrganizations/org2.example.com/msp/config.yaml \
   ${PWD}/organizations/peerOrganizations/org2.example.com/users/Ersultan@org2.example.com/msp/config.yaml

echo "✅ Done: Ruslan, Ersultan, SecurityService, MLService enrolled with attrs."
"""
    run_bash_block(script)

def main():
    print("=" * 45)
    print("🔨 FABRIC INIT (CA + USERS WITH ATTRS)")
    print("ВНИМАНИЕ: Все старые данные будут удалены!")
    print("=" * 45)

    # 1) down
    run_fabric_command("./network.sh down")

    # 2) up + channel + CA
    run_fabric_command("./network.sh up createChannel -ca")

    # 3) enroll users with attrs
    enroll_custom_identities()

    # 4) deploy chaincode (SKIP FOR NOW - Docker socket issue)
    # Try to deploy chaincode, but don't fail if it doesn't work
    print("\n🚀 Попытка развернуть chaincode...")
    try:
        run_fabric_command(
            "./network.sh deployCC "
            "-ccn securedata "
            "-ccp /home/ruslan/working/chaincode "
            "-ccl go",
            timeout=600  # Allow 10 minutes for chaincode deployment
        )
        print("✅ Chaincode развернут успешно!")
    except SystemExit:
        print("⚠️  Развертывание chaincode не удалось (Docker проблема)")
        print("   Сеть и пользователи готовы. Можно попробовать:")
        print("   cd /home/ruslan/fabric-dev/fabric-samples/test-network")
        print("   ./network.sh deployCC -ccn securedata -ccp /home/ruslan/working/chaincode -ccl go")

    print("\n" + "=" * 45)
    print("🎉 Сеть поднята с CA. Пользователи с атрибутами созданы.")
    print("Теперь можно запускать server.py")
    print("=" * 45)

if __name__ == "__main__":
    main()
