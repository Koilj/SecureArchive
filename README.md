# SecureData Archive

SecureData Archive - локальная платформа для хранения исследовательских данных:
файлы шифруются в браузере, зашифрованный контент хранится в IPFS/Kubo, права
доступа и аудит записываются в Hyperledger Fabric, вход выполняется через
WebAuthn/passkeys, а AI-сервис предлагает категорию метаданных.

Проект рассчитан на локальный dev/test стенд. Для production нужны отдельные
настройки TLS, доменов, секретов, мониторинга, бэкапов и политики хранения.

## Что внутри

| Часть | Путь | Назначение |
| --- | --- | --- |
| Frontend | `index.html`, `frontend/` | Статический UI без сборщика. WebAuthn, локальные ключи, шифрование, работа с Fabric через backend. |
| Backend | `server.py` | Flask API, WebAuthn-проверки, proxy для Fabric offline signing, загрузка/скачивание из IPFS, AI-интеграция. |
| Fabric agent | `agent-go/` | Go HTTP/CLI агент для обращения к Hyperledger Fabric Gateway. |
| Chaincode | `chaincode/` | Go smart contract `securedata`: пользователи, ассеты, доступы, аудит, invite flow. |
| AI service | `ai_service/` | FastAPI сервис SciBERT multilabel classification. |
| Sanitizer | `disp_sanitizer/` | Очистка и аудит метаданных загрузки. |
| Tests | `tests/` | Python, WebAuthn/recovery, IPFS и helper tests. |

## Архитектура в одном абзаце

Браузер хранит приватные пользовательские ключи локально: WebAuthn credential,
ключ шифрования данных и Fabric signing key. Backend не хранит пользовательские
private keys. Для операций Fabric backend готовит/проксирует данные, браузер
подписывает их локально, а Go agent отправляет транзакции в Fabric Gateway.
Файлы перед отправкой в backend шифруются в браузере; backend кладет только
ciphertext в IPFS/Kubo.

## Рекомендуемые версии

Эти версии подходят для текущего кода и локального Fabric test-network:

| Компонент | Версия |
| --- | --- |
| OS | Ubuntu 22.04/24.04 или WSL2 Ubuntu |
| Python | 3.10+ |
| Go | 1.24.x |
| Docker | 24+ |
| Docker Compose | v2+ |
| Hyperledger Fabric | 2.5.15 |
| Hyperledger Fabric CA | 1.5.17 |
| Kubo/IPFS | 0.26.0+ |

Почему Fabric `2.5.15`: официальный `install-fabric.sh` сейчас использует
`2.5.15` как default Fabric release и `1.5.17` как default Fabric CA release.
В проекте лучше фиксировать версии явно, а не полагаться на `latest`.

## Установка системных зависимостей

Ubuntu/WSL2:

```bash
sudo apt update
sudo apt install -y \
  git curl ca-certificates jq build-essential pkg-config \
  python3 python3-venv python3-pip
```

Docker:

```bash
docker --version
docker compose version
sudo usermod -aG docker "$USER"
```

После добавления пользователя в группу `docker` перелогиньтесь или откройте
новый терминал. Проверка:

```bash
docker run --rm hello-world
```

Go 1.24.x:

```bash
go version
```

Если Go не установлен, поставьте Go 1.24.x с официального сайта Go или через
ваш package manager. Для этого репозитория важно, чтобы `go version` показывал
`go1.24...`.

## Установка Hyperledger Fabric

Ставим Fabric Samples, Docker images и binaries в отдельную директорию:

```bash
mkdir -p "$HOME/fabric-dev"
cd "$HOME/fabric-dev"

curl -sSLO https://raw.githubusercontent.com/hyperledger/fabric/main/scripts/install-fabric.sh
chmod +x install-fabric.sh

./install-fabric.sh \
  --fabric-version 2.5.15 \
  --ca-version 1.5.17 \
  docker samples binary
```

После установки должны появиться:

```bash
$HOME/fabric-dev/fabric-samples/test-network
$HOME/fabric-dev/fabric-samples/bin
$HOME/fabric-dev/fabric-samples/config
```

Добавьте Fabric binaries в `PATH` для текущего терминала:

```bash
export FABRIC_PATH="$HOME/fabric-dev/fabric-samples/test-network"
export PATH="$HOME/fabric-dev/fabric-samples/bin:$PATH"
export FABRIC_CFG_PATH="$HOME/fabric-dev/fabric-samples/config"
```

Проверка:

```bash
peer version
fabric-ca-client version
```

## Установка проекта

Клонируйте или откройте репозиторий:

```bash
cd /home/ruslan/working
```

Python environment для backend:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

Python environment для AI service:

```bash
cd /home/ruslan/working/ai_service
python3 -m venv .venv-ai
source .venv-ai/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Go agent:

```bash
cd /home/ruslan/working/agent-go
go mod download
go build -o securedata-agent .
```

Chaincode dependencies:

```bash
cd /home/ruslan/working/chaincode
go mod download
go test ./...
```

## Локальная конфигурация

Создайте `.env.local` из примера:

```bash
cd /home/ruslan/working
cp .env.example .env.local
```

Замените секреты на реальные случайные значения:

```bash
python3 - <<'PY'
import secrets
for name in ("FLASK_SECRET", "INVITE_SIGNING_KEY", "SECURITY_AGENT_TOKEN"):
    print(f"{name}={secrets.token_urlsafe(48)}")
PY
```

Минимально важные значения в `.env.local`:

```bash
FABRIC_PATH=/home/ruslan/fabric-dev/fabric-samples/test-network
CHAINCODE_PATH=/home/ruslan/working/chaincode

HOST=127.0.0.1
PORT=5500

WEBAUTHN_RP_ID=localhost
WEBAUTHN_ORIGIN=http://localhost:8000
WEB_ORIGINS=http://localhost:8000,http://127.0.0.1:8000

AI_SERVICE_URL=http://127.0.0.1:8100
AI_SERVICE_AUTOSTART=0
AUTO_SUGGEST=1

AGENT_AUTOSTART=1
AGENT_IDENTITIES=SecurityService,MLService
AGENT_DISABLE_AUTH=0

IPFS_NODE_URLS=http://127.0.0.1:5011,http://127.0.0.1:5012
IPFS_MIN_REPLICAS=2
IPFS_TARGET_REPLICAS=2
IPFS_STRICT_CID=1
```

Загрузить `.env.local` в терминал:

```bash
cd /home/ruslan/working
set -a
source .env.local
set +a
```

Никогда не коммитьте `.env.local`, `.env`, приватные ключи, Fabric crypto
material, runtime state и локальные IPFS repos.

## Инициализация Fabric network

Команда ниже удаляет старое состояние test-network, поднимает сеть, создает
канал, регистрирует service identities и деплоит chaincode `securedata`.

```bash
cd /home/ruslan/working
source .venv/bin/activate
set -a
source .env.local
set +a

python3 -B init_network.py
```

Скрипт использует:

- `FABRIC_PATH` - путь к `fabric-samples/test-network`;
- `CHAINCODE_PATH` - путь к `chaincode/`;
- `BOOTSTRAP_USER` - по умолчанию `SecurityService`;
- `BOOTSTRAP_ENROLLMENT_SECRET` - по умолчанию `securitypw`.

## Запуск локального IPFS/Kubo

Проекту нужны минимум две Kubo API-ноды, потому что backend требует
`IPFS_MIN_REPLICAS=2`.

Пример ручного запуска двух локальных нод:

```bash
mkdir -p "$HOME/.securedata-ipfs/node-a" "$HOME/.securedata-ipfs/node-b"

IPFS_PATH="$HOME/.securedata-ipfs/node-a" ipfs init --profile=server --empty-repo
IPFS_PATH="$HOME/.securedata-ipfs/node-b" ipfs init --profile=server --empty-repo

IPFS_PATH="$HOME/.securedata-ipfs/node-a" ipfs config Addresses.API /ip4/127.0.0.1/tcp/5011
IPFS_PATH="$HOME/.securedata-ipfs/node-a" ipfs config Addresses.Gateway /ip4/127.0.0.1/tcp/8081
IPFS_PATH="$HOME/.securedata-ipfs/node-a" ipfs config Addresses.Swarm --json '["/ip4/127.0.0.1/tcp/4011"]'
IPFS_PATH="$HOME/.securedata-ipfs/node-a" ipfs config Bootstrap --json '[]'
IPFS_PATH="$HOME/.securedata-ipfs/node-a" ipfs config Datastore.StorageMax 5GB

IPFS_PATH="$HOME/.securedata-ipfs/node-b" ipfs config Addresses.API /ip4/127.0.0.1/tcp/5012
IPFS_PATH="$HOME/.securedata-ipfs/node-b" ipfs config Addresses.Gateway /ip4/127.0.0.1/tcp/8082
IPFS_PATH="$HOME/.securedata-ipfs/node-b" ipfs config Addresses.Swarm --json '["/ip4/127.0.0.1/tcp/4012"]'
IPFS_PATH="$HOME/.securedata-ipfs/node-b" ipfs config Bootstrap --json '[]'
IPFS_PATH="$HOME/.securedata-ipfs/node-b" ipfs config Datastore.StorageMax 5GB
```

Запуск в двух отдельных терминалах:

```bash
IPFS_PATH="$HOME/.securedata-ipfs/node-a" ipfs daemon
```

```bash
IPFS_PATH="$HOME/.securedata-ipfs/node-b" ipfs daemon
```

Проверка:

```bash
curl -s -X POST http://127.0.0.1:5011/api/v0/version | jq
curl -s -X POST http://127.0.0.1:5012/api/v0/version | jq
```

Для unit tests можно использовать `mock_ipfs_node.py`, но для ручного демо и
проверки хранения используйте настоящий Kubo.

## Запуск сервисов

Откройте отдельные терминалы.

### 1. AI service

```bash
cd /home/ruslan/working/ai_service
source .venv-ai/bin/activate
python -B main.py
```

Проверка:

```bash
curl -s http://127.0.0.1:8100/health | jq
```

Если директория `scibert_multilabel_v3/` отсутствует, AI service запустится, но
вернет `ready=false`; основная система при этом может работать без реальной
AI-классификации.

### 2. Backend и Go agent

`AGENT_AUTOSTART=1` означает, что `server.py` сам запустит
`agent-go/securedata-agent serve-unified`.

```bash
cd /home/ruslan/working
source .venv/bin/activate
set -a
source .env.local
set +a

python3 -B server.py
```

Проверки:

```bash
curl -s http://127.0.0.1:5500/health | jq
curl -s http://127.0.0.1:5500/health/ipfs | jq
curl -s http://127.0.0.1:8090/health | jq
```

Если хотите запускать agent вручную:

```bash
cd /home/ruslan/working/agent-go
set -a
source /home/ruslan/working/.env.local
set +a

export AGENT_TOKEN="$SECURITY_AGENT_TOKEN"
export AGENT_HTTP_ADDR=127.0.0.1:8090
go run . serve-unified
```

Тогда в backend выставьте `AGENT_AUTOSTART=0`.

### 3. Frontend

```bash
cd /home/ruslan/working
python3 -B -m http.server 8000
```

Открывайте именно:

```text
http://localhost:8000/
```

Не используйте `http://127.0.0.1:8000/` для WebAuthn/passkeys. RP ID настроен
как `localhost`, и часть браузеров строго проверяет origin/RP binding.

## Первый вход

1. Откройте `http://localhost:8000/`.
2. Выполните bootstrap/activation для `SecurityService`.
3. Браузер создаст passkey, data-encryption key и Fabric signing key.
4. Backend зарегистрирует/выпустит Fabric certificate через CA.
5. После входа в `SecurityService` создавайте invite tickets для других users.

## Роли

| Role | Назначение |
| --- | --- |
| `SecurityService` | Администрирование users/invites, аудит, security actions, полный обзор assets. |
| `Researcher` | Загрузка файлов, запросы доступа, скачивание разрешенных assets. |
| `MLService` | Внутренная роль для AI suggestions. |
| `RiskService` | Внутренняя роль для risk/block automation. |

UI скрывает лишние вкладки по роли, но реальная авторизация находится в
chaincode и backend.

## Основные backend endpoints

| Endpoint | Назначение |
| --- | --- |
| `GET /health` | Backend + AI status. |
| `GET /health/ipfs` | Состояние Kubo нод и реплик. |
| `POST /auth/bootstrap-ticket` | Bootstrap ticket для первого SecurityService. |
| `POST /auth/activate/options` / `POST /auth/activate/finish` | Активация пользователя и passkey. |
| `POST /auth/login/options` / `POST /auth/login/verify` | Вход через WebAuthn. |
| `POST /fabric/eval` | Offline signed Fabric evaluate flow. |
| `POST /fabric/submit` | Offline signed Fabric submit flow. |
| `POST /upload` | Прием encrypted bytes и запись в IPFS. |
| `POST /download/asset/<asset_id>` | Скачивание разрешенного encrypted asset. |
| `GET /audit/disp` | DISP sanitizer audit, только для SecurityService. |

Go agent слушает `127.0.0.1:8090`:

| Endpoint | Назначение |
| --- | --- |
| `GET /health` | Agent health. |
| `POST /eval` | Fabric evaluate. |
| `POST /submit` | Fabric submit. |

AI service слушает `127.0.0.1:8100`:

| Endpoint | Назначение |
| --- | --- |
| `GET /health` | Model/service status. |
| `POST /predict` | Одна классификация. |
| `POST /predict/batch` | Batch classification. |

## Тесты

Backend/helper tests:

```bash
cd /home/ruslan/working
source .venv/bin/activate
python -m pytest tests/
```

Go agent:

```bash
cd /home/ruslan/working/agent-go
go test ./...
```

Chaincode:

```bash
cd /home/ruslan/working/chaincode
go test ./...
```

Playwright Chromium, если нужны browser tests:

```bash
cd /home/ruslan/working
source .venv/bin/activate
python -m playwright install chromium
python -m pytest tests/test_recovery_bundle.py tests/test_recovery_reissue.py
```

Real IPFS tests требуют `ipfs` в `PATH`:

```bash
cd /home/ruslan/working
source .venv/bin/activate
python -m pytest tests/test_ipfs_real.py -v --timeout=120
```

## Частые проблемы

### `docker: permission denied`

Пользователь не в группе `docker` или терминал открыт до изменения группы:

```bash
sudo usermod -aG docker "$USER"
```

Потом перелогиньтесь.

### `fabric-ca-client: command not found`

Fabric binaries не добавлены в `PATH`:

```bash
export PATH="$HOME/fabric-dev/fabric-samples/bin:$PATH"
```

### `FABRIC_PATH is empty`

Не загружен `.env.local` или переменная не задана:

```bash
set -a
source /home/ruslan/working/.env.local
set +a
```

### WebAuthn/passkey не работает

Откройте `http://localhost:8000/`, а не `127.0.0.1`. Также не используйте
private/incognito profile и встроенный browser IDE.

### IPFS health показывает меньше двух healthy nodes

Проверьте, что обе Kubo ноды запущены и доступны:

```bash
curl -s -X POST http://127.0.0.1:5011/api/v0/version | jq
curl -s -X POST http://127.0.0.1:5012/api/v0/version | jq
```

### AI service `ready=false`

Нет локальной директории модели `scibert_multilabel_v3/` или не хватает
зависимостей TensorFlow/Transformers. Основные upload/access flows могут
работать без готовой AI-модели.

## Что не коммитить

Проверьте `.gitignore`. В GitHub не должны попадать:

- `.env`, `.env.local`;
- `.venv/`, `ai_service/.venv-ai/`;
- `agent-go/securedata-agent`;
- `scibert_multilabel_v3/`;
- `~/.securedata-run/`, `~/.securedata-ipfs/`;
- Fabric runtime state из `fabric-samples/test-network/organizations`;
- временные логи, backups, test reports.

## Полезные ссылки

- Hyperledger Fabric install docs: https://hyperledger-fabric.readthedocs.io/en/latest/install.html
- Hyperledger Fabric test network docs: https://hyperledger-fabric.readthedocs.io/en/latest/test_network.html
- Kubo docs: https://docs.ipfs.tech/install/command-line/
