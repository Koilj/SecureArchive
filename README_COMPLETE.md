# 🔐 SecureData Archive - Launch Guide

**Simple step-by-step instructions to launch your system.**

---

## Requirements

- OS: Linux (Ubuntu/Debian recommended)
- Python: 3.10.x (venv recommended)
- Go: 1.24+
- Docker: 20+ (tested with Docker 28.5.2) and Docker Compose
- Hyperledger Fabric: Version: v3.0.0
- IPFS (kubo) CLI & daemon (API on port 5001)
- Git and Git LFS (recommended for large binaries)

Quick Python setup:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Notes:
- Ensure `FABRIC_PATH` points to your local `fabric-samples/test-network` (example: `/home/ruslan/fabric-dev/fabric-samples/test-network`).
- Large files (model, dataset) should be stored with Git LFS or placed outside the repo.

---

## Step 1: Initialize Fabric Network

Run this command once to start the blockchain infrastructure:

```bash
python3 init_network.py
```
Analyze the project completely. And tell me what improvements could be made to it?
⏱️ **Takes a few minutes** | Shows network is ready when complete

---

## Step 2: Start 4 Go Agent Services

Open 4 separate terminals and run these commands (one per terminal):

### Terminal 2A - SecurityService (Port 8090)
```bash
cd /home/ruslan/working/agent-go
export FABRIC_PATH=/home/ruslan/fabric-dev/fabric-samples/test-network

export AGENT_ORG=org1
export AGENT_USER=SecurityService
export AGENT_MSPID=Org1MSP
export AGENT_PEER_ENDPOINT=localhost:7051
export AGENT_PEER_HOST=peer0.org1.example.com
export AGENT_HTTP_ADDR=127.0.0.1:8090
export AGENT_TOKEN=security_token_123

go run . serve
```

### Terminal 2B - MLService (Port 8091)
```bash
cd /home/ruslan/working/agent-go
export FABRIC_PATH=/home/ruslan/fabric-dev/fabric-samples/test-network

export AGENT_ORG=org1
export AGENT_USER=MLService
export AGENT_MSPID=Org1MSP
export AGENT_PEER_ENDPOINT=localhost:7051
export AGENT_PEER_HOST=peer0.org1.example.com
export AGENT_HTTP_ADDR=127.0.0.1:8091
export AGENT_TOKEN=ml_token_123

go run . serve
```

### Terminal 2C - Ruslan User (Port 8088)
```bash
cd /home/ruslan/working/agent-go
export FABRIC_PATH=/home/ruslan/fabric-dev/fabric-samples/test-network

export AGENT_ORG=org1
export AGENT_USER=Ruslan
export AGENT_MSPID=Org1MSP
export AGENT_PEER_ENDPOINT=localhost:7051
export AGENT_PEER_HOST=peer0.org1.example.com
export AGENT_HTTP_ADDR=127.0.0.1:8088
export AGENT_TOKEN=ruslan_token_123

go run . serve
```

### Terminal 2D - Ersultan User (Port 8089)
```bash
cd /home/ruslan/working/agent-go
export FABRIC_PATH=/home/ruslan/fabric-dev/fabric-samples/test-network

export AGENT_ORG=org2
export AGENT_USER=Ersultan
export AGENT_MSPID=Org2MSP
export AGENT_PEER_ENDPOINT=localhost:9051
export AGENT_PEER_HOST=peer0.org2.example.com
export AGENT_HTTP_ADDR=127.0.0.1:8089
export AGENT_TOKEN=ersultan_token_123

go run . serve
```

✅ **Wait for:** "Listening on..." message in each terminal

---

## Step 3: Health Check

Open new terminal and verify all 4 agents are responding:

```bash
curl -s http://127.0.0.1:8088/health
curl -s http://127.0.0.1:8089/health
curl -s http://127.0.0.1:8090/health
curl -s http://127.0.0.1:8091/health
echo
```

Expected: `{"ok":true}` for each agent

---

## Step 4: Test Agent Functions

### 4.1 - Check ML Agent Identity
```bash
curl -s http://127.0.0.1:8091/eval \
  -H "Authorization: Bearer ml_token_123" \
  -H "Content-Type: application/json" \
  -d '{"function":"WhoAmI","args":[]}'
```

### 4.2 - Bind Service Identity
```bash
curl -s http://127.0.0.1:8090/submit \
  -H "Authorization: Bearer security_token_123" \
  -H "Content-Type: application/json" \
  -d '{"function":"BindServiceIdentity","args":["MLService","<CLIENT_ID_FROM_WHOAMI>"]}'
```

---

## Step 5: Register Users

### 5.1 - Register Ruslan
```bash
python3 - <<'PY' | curl -s http://127.0.0.1:8088/submit \
  -H "Authorization: Bearer ruslan_token_123" \
  -H "Content-Type: application/json" \
  --data-binary @-
import json, subprocess
pub = subprocess.check_output(["curl","-s","http://127.0.0.1:8088/rsa/publicKey"]).decode()
print(json.dumps({"function":"RegisterUser","args":["Ruslan", pub, "", ""]}))
PY
echo
```

### 5.2 - Register Ersultan
```bash
python3 - <<'PY' | curl -s http://127.0.0.1:8089/submit \
  -H "Authorization: Bearer ersultan_token_123" \
  -H "Content-Type: application/json" \
  --data-binary @-
import json, subprocess
pub = subprocess.check_output(["curl","-s","http://127.0.0.1:8089/rsa/publicKey"]).decode()
print(json.dumps({"function":"RegisterUser","args":["Ersultan", pub, "", ""]}))
PY
echo
```

---

## Step 6: Start Flask Backend

Open new terminal:

```bash
cd /home/ruslan/working
source venv/bin/activate

export ML_AGENT_URL=http://127.0.0.1:8091
export ML_AGENT_TOKEN=ml_token_123

python3 server.py
```

Expected: `* Running on http://0.0.0.0:5000`

---
>
## Step 7: Start Web Server

Open new terminal:

```bash
cd /home/ruslan/working
python3 -m http.server 8000
```

Expected: `Serving HTTP on 0.0.0.0 port 8000`

---

## Step 8: Access the UI

Open your browser:

```
http://127.0.0.1:8000/
```

You should see the SecureData Archive interface where you can:
- Upload documents
- View assets
- Manage access
- Check audit logs

---

## 📋 What's Running

| Port | Service |
|------|---------|
| 8000 | Web UI |
| 5000 | Flask API |
| 5001 | IPFS (auto-running) |
| 8088 | Ruslan Agent |
| 8089 | Ersultan Agent |
| 8090 | SecurityService Agent |
| 8091 | MLService Agent |

---

## 🔧 Stop Everything

To stop all services, press `Ctrl+C` in each terminal.

To clean up completely:
```bash
docker-compose -f /home/ruslan/fabric-dev/fabric-samples/test-network/docker-compose-test-net.yaml down -v
```

---

---

## 📤 Publishing this Project to GitHub (recommended)

1) Initialize git (if not already):

```bash
cd /home/ruslan/working
git init
git add .gitignore .gitattributes
git lfs install --local || true
# Track large files with Git LFS (only if you use LFS)
git lfs track "*.h5" "*.pickle" "arxiv-metadata-oai-snapshot.json" "working.zip"
git add .gitattributes
git add .
git commit -m "Initial commit - SecureData Archive (no large datasets)"
```

2) Create a remote repository on GitHub (web) or use the GitHub CLI:

```bash
# with gh (optional):
gh repo create YOUR_USERNAME/SecureData-Archive --public --source=. --remote=origin
# or create via GitHub website and then:
git remote add origin git@github.com:YOUR_USERNAME/SecureData-Archive.git
git branch -M main
git push -u origin main
```

Notes & best practices:
- Do NOT commit `venv/`, datasets, or built artifacts. Use the `.gitignore` already included.
- Use Git LFS for large binary files (models, datasets). If you need to add large files later, run `git lfs track` first, then add and commit.
- If you accidentally committed large files, remove them from the index before pushing:

```bash
git rm --cached -r venv
git commit -m "Remove venv from repository"
```

- To purge large files from history use `git filter-repo` or BFG (requires care):
  - `git filter-repo --path classifier_model.h5 --invert-paths`
  - or follow BFG repo-cleaner instructions

3) Recommended repo layout adjustments before publishing:
- Move huge datasets (e.g., `arxiv-metadata-oai-snapshot.json`) out of the repository or host them in releases or cloud storage.
- Keep `classifier_model.h5` and other trained artifacts under Git LFS or in a release asset.

---

**Status:** ✅ Ready to Launch


