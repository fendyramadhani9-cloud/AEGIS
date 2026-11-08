#!/usr/bin/env bash
# ==============================================================================
# AEGIS Linux Host Agent Installer (1-Click Systemd Service Setup)
# Target: Ubuntu 22.04 / 24.04 LTS Mini Server
# Purpose: Installs native telemetry & security checker collector directly on host
#          to monitor systemd, journalctl, ufw, auditd, and /var/log/* without
#          container isolation limits, streaming data to AEGIS Docker on port 1708.
# ==============================================================================

set -e

# Default settings
DEFAULT_API_URL="http://127.0.0.1:1708/api"
DEFAULT_TOKEN="aegis-agent-dev-secret-token"
DEFAULT_HOST_ID="host-$(hostname -s)"
DEFAULT_TENANT_ID="default"
INSTALL_DIR="/opt/aegis-agent"
CONFIG_DIR="/etc/aegis"
STATE_DIR="/var/lib/aegis"
SERVICE_NAME="aegis-collector"

API_URL="${DEFAULT_API_URL}"
TOKEN="${DEFAULT_TOKEN}"
HOST_ID="${DEFAULT_HOST_ID}"
TENANT_ID="${DEFAULT_TENANT_ID}"

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

print_banner() {
    echo -e "${BLUE}"
    echo "=================================================================="
    echo "      AEGIS DEFENSE PLATFORM — NATIVE HOST AGENT INSTALLER        "
    echo "           Military & Defense Infrastructure Monitoring           "
    echo "=================================================================="
    echo -e "${NC}"
}

usage() {
    echo "Usage: sudo $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --api-url <URL>        AEGIS Backend API URL (default: ${DEFAULT_API_URL})"
    echo "  --server-url <URL>     Alias for --api-url"
    echo "  --token <TOKEN>        Agent Ingestion Secret Token (default: dev token or from .env)"
    echo "  --auth-token <TOKEN>   Alias for --token"
    echo "  --tenant-id <TENANT>   Tenant / Battalion ID for Multi-Tenant Isolation"
    echo "  --host-id <ID>         Custom Host Identifier (default: ${DEFAULT_HOST_ID})"
    echo "  --uninstall            Stop and completely remove AEGIS Host Agent"
    echo "  -h, --help             Show this help message"
    echo ""
    exit 0
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --api-url|--server-url)
            API_URL="$2"
            shift 2
            ;;
        --token|--auth-token)
            TOKEN="$2"
            shift 2
            ;;
        --tenant-id|--tenant)
            TENANT_ID="$2"
            shift 2
            ;;
        --host-id)
            HOST_ID="$2"
            shift 2
            ;;
        --uninstall)
            UNINSTALL_MODE=true
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo -e "${RED}[!] Unknown argument: $1${NC}"
            usage
            ;;
    esac
done

# Check root privilege
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[!] Error: This script must be run as root (use sudo).${NC}"
   exit 1
fi

print_banner

# Handle Uninstall
if [[ "${UNINSTALL_MODE}" == "true" ]]; then
    echo -e "${YELLOW}[*] Stopping and disabling ${SERVICE_NAME}.service...${NC}"
    systemctl stop ${SERVICE_NAME} 2>/dev/null || true
    systemctl disable ${SERVICE_NAME} 2>/dev/null || true
    rm -f /etc/systemd/system/${SERVICE_NAME}.service
    systemctl daemon-reload

    echo -e "${YELLOW}[*] Removing installation files (${INSTALL_DIR}, ${CONFIG_DIR})...${NC}"
    rm -rf "${INSTALL_DIR}"
    rm -rf "${CONFIG_DIR}"
    
    echo -e "${GREEN}[✓] AEGIS Host Agent has been completely uninstalled.${NC}"
    exit 0
fi

# Detect project root from script location
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Check if .env exists in repo root for token fallback
if [[ -f "${REPO_ROOT}/.env" && "${TOKEN}" == "${DEFAULT_TOKEN}" ]]; then
    ENV_TOKEN=$(grep -E "^AGENT_INGEST_TOKEN=" "${REPO_ROOT}/.env" | cut -d'=' -f2- | tr -d '"' | tr -d "'")
    if [[ -n "${ENV_TOKEN}" && "${ENV_TOKEN}" != "your_secure_agent_ingest_token_here" ]]; then
        TOKEN="${ENV_TOKEN}"
        echo -e "${BLUE}[*] Extracted AGENT_INGEST_TOKEN from existing .env${NC}"
    fi
fi

echo -e "${BLUE}[1/6] Installing necessary system dependencies (Python3, venv, pip, curl)...${NC}"
apt-get update -qq
apt-get install -y -qq python3 python3-venv python3-pip curl systemd

echo -e "${BLUE}[2/6] Creating agent directory structure (${INSTALL_DIR}, ${CONFIG_DIR}, ${STATE_DIR})...${NC}"
mkdir -p "${INSTALL_DIR}"
mkdir -p "${CONFIG_DIR}"
mkdir -p "${STATE_DIR}"
chmod 750 "${INSTALL_DIR}"
chmod 700 "${CONFIG_DIR}"
chmod 700 "${STATE_DIR}"

echo -e "${BLUE}[3/6] Deploying agent source modules to ${INSTALL_DIR}...${NC}"
cp -r "${REPO_ROOT}/aegis_agent" "${INSTALL_DIR}/"
mkdir -p "${INSTALL_DIR}/aegis_backend"
cp "${REPO_ROOT}/aegis_backend/sanitizer.py" "${INSTALL_DIR}/aegis_backend/"
touch "${INSTALL_DIR}/aegis_backend/__init__.py"

echo -e "${BLUE}[4/6] Creating isolated Python virtualenv and installing dependencies...${NC}"
python3 -m venv "${INSTALL_DIR}/venv"
"${INSTALL_DIR}/venv/bin/pip" install --quiet --upgrade pip
"${INSTALL_DIR}/venv/bin/pip" install --quiet requests pydantic python-dotenv

echo -e "${BLUE}[5/6] Writing configuration file (${CONFIG_DIR}/agent.env)...${NC}"
cat <<EOF > "${CONFIG_DIR}/agent.env"
# AEGIS Host Agent Runtime Configuration
AEGIS_API_URL=${API_URL}
AGENT_INGEST_TOKEN=${TOKEN}
AEGIS_TENANT_ID=${TENANT_ID}
AEGIS_HOST_ID=${HOST_ID}
AEGIS_HOSTNAME=$(hostname)
AEGIS_IP_ADDRESS=$(hostname -I | awk '{print $1}')
AEGIS_OS_NAME=$(grep -oP '(?<=PRETTY_NAME=")[^"]*' /etc/os-release 2>/dev/null || echo "Ubuntu Linux")
AEGIS_POLL_INTERVAL=15
AEGIS_HEARTBEAT_INTERVAL=60
AEGIS_POSTURE_INTERVAL=300
AEGIS_CURSOR_FILE=${STATE_DIR}/collector_cursor
AEGIS_LOG_FILES=/var/log/nginx/access.log,/var/log/apache2/access.log,/var/log/audit/audit.log
EOF
chmod 600 "${CONFIG_DIR}/agent.env"

echo -e "${BLUE}[6/6] Creating and activating systemd service (${SERVICE_NAME}.service)...${NC}"
cat <<EOF > "/etc/systemd/system/${SERVICE_NAME}.service"
[Unit]
Description=AEGIS Security Telemetry & Posture Collector
Documentation=https://github.com/fendyramadhani9-cloud/AEGIS
After=network.target docker.service

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
EnvironmentFile=${CONFIG_DIR}/agent.env
ExecStart=${INSTALL_DIR}/venv/bin/python3 -m aegis_agent.collector
Restart=always
RestartSec=5

# Defensive isolation: protect host filesystem while retaining read-only observability
ProtectSystem=full
ProtectHome=read-only
ReadWritePaths=${STATE_DIR}

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now "${SERVICE_NAME}"

# Verify active status
sleep 2
if systemctl is-active --quiet "${SERVICE_NAME}"; then
    echo -e "${GREEN}"
    echo "=================================================================="
    echo "  [✓] AEGIS HOST AGENT INSTALLED AND RUNNING SUCCESSFULLY!        "
    echo "=================================================================="
    echo -e "${NC}"
    echo -e "  Host ID       : ${GREEN}${HOST_ID}${NC}"
    echo -e "  Tenant ID     : ${GREEN}${TENANT_ID}${NC}"
    echo -e "  Target Gateway: ${GREEN}${API_URL}${NC}"
    echo -e "  Service Name  : ${GREEN}${SERVICE_NAME}.service${NC}"
    echo -e "  Config File   : ${CONFIG_DIR}/agent.env"
    echo -e "  State File    : ${STATE_DIR}/collector_cursor"
    echo ""
    echo "Useful operational commands:"
    echo -e "  • Check status : ${YELLOW}sudo systemctl status ${SERVICE_NAME}${NC}"
    echo -e "  • View live log: ${YELLOW}sudo journalctl -u ${SERVICE_NAME} -f${NC}"
    echo -e "  • Restart agent: ${YELLOW}sudo systemctl restart ${SERVICE_NAME}${NC}"
    echo -e "  • Uninstall    : ${YELLOW}sudo $0 --uninstall${NC}"
    echo ""
else
    echo -e "${RED}[!] Warning: Service started but is not reporting active status.${NC}"
    echo -e "Check logs with: sudo journalctl -u ${SERVICE_NAME} -n 30 --no-pager"
    exit 1
fi
