#!/usr/bin/env bash
# ==============================================================================
# AEGIS Linux Host Agent Uninstaller
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
sudo "${SCRIPT_DIR}/install_agent.sh" --uninstall

