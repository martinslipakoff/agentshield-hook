#!/bin/bash
set -euo pipefail

# ── AgentShield Installer ────────────────────────────────────────────────────
# Installs the AgentShield hook for Claude Code.
#
# Usage:
#   curl -sSL https://YOUR_DOMAIN/install.sh | bash -s -- --key <KEY> --url <URL>
#
#   Or interactively:
#   curl -sSL https://YOUR_DOMAIN/install.sh | bash
#
# What it does:
#   1. Creates ~/.agentshield/ with config and hook script
#   2. Configures ~/.claude/hooks.json to use AgentShield
#   3. Sends a test event to verify connectivity
# ─────────────────────────────────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

INSTALL_DIR="$HOME/.agentshield"
CONFIG_FILE="$INSTALL_DIR/config.json"
HOOK_SCRIPT="$INSTALL_DIR/hook.py"
CLAUDE_HOOKS_FILE="$HOME/.claude/hooks.json"

# ── Parse arguments ──────────────────────────────────────────────────────────

COLLECTOR_KEY=""
API_URL=""
MACHINE_NAME="$(hostname -s 2>/dev/null || hostname)"
UNINSTALL=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --key)       COLLECTOR_KEY="$2"; shift 2 ;;
        --url)       API_URL="$2"; shift 2 ;;
        --machine)   MACHINE_NAME="$2"; shift 2 ;;
        --uninstall) UNINSTALL=true; shift ;;
        --help|-h)
            echo "Usage: install.sh [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --key <KEY>       Collector API key (from AgentShield dashboard)"
            echo "  --url <URL>       AgentShield API URL (Supabase functions URL)"
            echo "  --machine <NAME>  Machine name (default: hostname)"
            echo "  --uninstall       Remove AgentShield hooks and config"
            echo "  --help            Show this help"
            exit 0
            ;;
        *) shift ;;
    esac
done

# ── Uninstall ────────────────────────────────────────────────────────────────

if [ "$UNINSTALL" = true ]; then
    echo -e "${YELLOW}Removing AgentShield...${NC}"

    # Remove hooks from Claude Code config
    if [ -f "$CLAUDE_HOOKS_FILE" ] && command -v python3 &>/dev/null; then
        python3 -c "
import json, os
hooks_file = '$CLAUDE_HOOKS_FILE'
try:
    with open(hooks_file) as f:
        data = json.load(f)
    hooks = data.get('hooks', {})
    for event_type in list(hooks.keys()):
        hooks[event_type] = [
            entry for entry in hooks[event_type]
            if not any('agentshield' in h.get('command', '') for h in entry.get('hooks', []))
        ]
        if not hooks[event_type]:
            del hooks[event_type]
    data['hooks'] = hooks
    with open(hooks_file, 'w') as f:
        json.dump(data, f, indent=2)
    print('Removed AgentShield from hooks.json')
except Exception as e:
    print(f'Warning: could not update hooks.json: {e}')
"
    fi

    # Remove install directory
    if [ -d "$INSTALL_DIR" ]; then
        rm -rf "$INSTALL_DIR"
        echo -e "${GREEN}Removed $INSTALL_DIR${NC}"
    fi

    echo -e "${GREEN}AgentShield uninstalled.${NC}"
    exit 0
fi

# ── Banner ───────────────────────────────────────────────────────────────────

echo ""
echo -e "${BLUE}${BOLD}  AgentShield Installer${NC}"
echo -e "${BLUE}  Secure your AI agent workflow${NC}"
echo ""

# ── Prerequisites ────────────────────────────────────────────────────────────

MISSING=""

if ! command -v python3 &>/dev/null; then
    MISSING="${MISSING}  - python3\n"
fi

if ! command -v curl &>/dev/null; then
    MISSING="${MISSING}  - curl\n"
fi

if [ -n "$MISSING" ]; then
    echo -e "${RED}Missing required tools:${NC}"
    echo -e "$MISSING"
    exit 1
fi

# Check Python version (need 3.6+ for f-strings)
PY_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PY_MAJOR=$(echo "$PY_VERSION" | cut -d. -f1)
PY_MINOR=$(echo "$PY_VERSION" | cut -d. -f2)
if [ "$PY_MAJOR" -lt 3 ] || ([ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 6 ]); then
    echo -e "${RED}Python 3.6+ required (found $PY_VERSION)${NC}"
    exit 1
fi

echo -e "${GREEN}Prerequisites OK${NC} (python $PY_VERSION, curl)"

# ── Prompt for missing values ────────────────────────────────────────────────

if [ -z "$API_URL" ]; then
    echo ""
    echo -e "${BOLD}Enter your AgentShield API URL${NC}"
    echo -e "  (from the dashboard Setup page, e.g. https://xxx.supabase.co/functions/v1)"
    read -rp "  API URL: " API_URL
fi

if [ -z "$API_URL" ]; then
    echo -e "${RED}API URL is required.${NC}"
    exit 1
fi

if [ -z "$COLLECTOR_KEY" ]; then
    echo ""
    echo -e "${BOLD}Enter your Collector Key${NC}"
    echo -e "  (from the dashboard Setup page, starts with as_live_)"
    read -rp "  Key: " COLLECTOR_KEY
fi

if [ -z "$COLLECTOR_KEY" ]; then
    echo -e "${RED}Collector key is required.${NC}"
    exit 1
fi

echo ""
DEFAULT_MACHINE="$MACHINE_NAME"
read -rp "Machine name [$DEFAULT_MACHINE]: " INPUT_MACHINE
MACHINE_NAME="${INPUT_MACHINE:-$DEFAULT_MACHINE}"

# ── Create directories ───────────────────────────────────────────────────────

mkdir -p "$INSTALL_DIR"
mkdir -p "$HOME/.claude"

echo ""
echo -e "${GREEN}[1/4]${NC} Created $INSTALL_DIR"

# ── Write config ─────────────────────────────────────────────────────────────

cat > "$CONFIG_FILE" << CONFIGEOF
{
  "api_url": "$API_URL",
  "collector_key": "$COLLECTOR_KEY",
  "machine_name": "$MACHINE_NAME",
  "default_agent": "claude",
  "mode": "block",
  "alert_threshold": 60,
  "block_threshold": 80,
  "allowlist_commands": []
}
CONFIGEOF

chmod 600 "$CONFIG_FILE"
echo -e "${GREEN}[2/4]${NC} Configuration saved (permissions: 600)"

# ── Write hook script ────────────────────────────────────────────────────────
# If hook.py exists alongside install.sh (local install), copy it.
# Otherwise, download from the same base URL as install.sh.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}" 2>/dev/null)" && pwd 2>/dev/null || echo "")"

if [ -n "$SCRIPT_DIR" ] && [ -f "$SCRIPT_DIR/hook.py" ]; then
    cp "$SCRIPT_DIR/hook.py" "$HOOK_SCRIPT"
else
    # Try to download from GitHub or hosted URL
    # Replace this URL with your actual hosted location
    HOOK_URL="${AGENTSHIELD_HOOK_URL:-https://raw.githubusercontent.com/martinslipakoff/agentshield-hook/main/hook.py}"
    if curl -sSfL "$HOOK_URL" -o "$HOOK_SCRIPT" 2>/dev/null; then
        :
    else
        echo -e "${RED}Could not download hook.py from $HOOK_URL${NC}"
        echo -e "${YELLOW}Place hook.py next to install.sh and run again, or set AGENTSHIELD_HOOK_URL${NC}"
        exit 1
    fi
fi

chmod +x "$HOOK_SCRIPT"
echo -e "${GREEN}[3/4]${NC} Hook script installed"

# ── Configure Claude Code hooks ──────────────────────────────────────────────

python3 << 'PYEOF'
import json, os, sys

home = os.path.expanduser("~")
hook_cmd = f"python3 {home}/.agentshield/hook.py"

agentshield_hooks = {
    "PreToolUse": [
        {
            "matcher": ".*",
            "hooks": [
                {
                    "type": "command",
                    "command": f"{hook_cmd} pre",
                }
            ],
        }
    ],
    "PostToolUse": [
        {
            "matcher": ".*",
            "hooks": [
                {
                    "type": "command",
                    "command": f"{hook_cmd} post",
                }
            ],
        }
    ],
}

def merge_hooks(file_path, hooks_data):
    """Load existing file, merge agentshield hooks, write back."""
    if os.path.exists(file_path):
        try:
            with open(file_path) as f:
                data = json.load(f)
        except json.JSONDecodeError:
            data = {}
    else:
        data = {}

    hooks = data.get("hooks", {})

    for event_type, new_entries in hooks_data.items():
        if event_type not in hooks:
            hooks[event_type] = []

        # Remove existing agentshield hooks (avoid duplicates on re-install)
        hooks[event_type] = [
            entry
            for entry in hooks[event_type]
            if not any(
                "agentshield" in h.get("command", "") for h in entry.get("hooks", [])
            )
        ]

        # Add new agentshield hooks
        hooks[event_type].extend(new_entries)

    data["hooks"] = hooks

    with open(file_path, "w") as f:
        json.dump(data, f, indent=2)

# Write to BOTH settings.json and hooks.json for compatibility
claude_dir = os.path.join(home, ".claude")
os.makedirs(claude_dir, exist_ok=True)

settings_file = os.path.join(claude_dir, "settings.json")
hooks_file = os.path.join(claude_dir, "hooks.json")

merge_hooks(settings_file, agentshield_hooks)
print("  - settings.json updated (primary)")

merge_hooks(hooks_file, agentshield_hooks)
print("  - hooks.json updated (fallback)")
PYEOF

echo -e "${GREEN}[4/4]${NC} Claude Code hooks configured"

# ── Test connection ──────────────────────────────────────────────────────────

echo ""
echo -e "${BOLD}Testing connection...${NC}"

TEST_EVENT=$(python3 -c "
import json, uuid
from datetime import datetime, timezone
event = {
    'id': f'evt-{uuid.uuid4()}',
    'session_id': 'setup-test',
    'tool': 'test',
    'command': 'agentshield installation test',
    'hash': '',
    'previous_hash': 'genesis',
    'signature': '',
    'timestamp': datetime.now(timezone.utc).isoformat(),
    'agent': 'installer',
    'machine': '$MACHINE_NAME',
    'project': 'agentshield-setup',
    'event_type': 'notification',
    'severity': 'info',
    'risk_score': 0,
    'blocked': False,
    'source': 'hook'
}
print(json.dumps([event]))
")

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$API_URL/ingest-events" \
    -H "Content-Type: application/json" \
    -H "x-collector-key: $COLLECTOR_KEY" \
    -d "$TEST_EVENT" \
    --max-time 10 2>/dev/null || echo "000")

if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
    echo -e "${GREEN}Connection successful!${NC}"
else
    echo -e "${YELLOW}Connection test returned HTTP $HTTP_CODE${NC}"
    if [ "$HTTP_CODE" = "401" ]; then
        echo -e "  Check your collector key"
    elif [ "$HTTP_CODE" = "000" ]; then
        echo -e "  Could not reach $API_URL — check the URL"
    else
        echo -e "  The hook will still work — events will be retried"
    fi
fi

# ── Done ─────────────────────────────────────────────────────────────────────

echo ""
echo -e "${GREEN}${BOLD}AgentShield installed successfully!${NC}"
echo ""
echo -e "  Config:      $CONFIG_FILE"
echo -e "  Hook:        $HOOK_SCRIPT"
echo -e "  Claude hooks: $CLAUDE_HOOKS_FILE"
echo -e "  Logs:        $INSTALL_DIR/hook.log"
echo ""
echo -e "  ${BOLD}Next steps:${NC}"
echo -e "  1. Restart Claude Code (or start a new session)"
echo -e "  2. Run any command — you'll see AgentShield monitoring in the dashboard"
echo ""
echo -e "  To change settings:  edit $CONFIG_FILE"
echo -e "  To view logs:        tail -f $INSTALL_DIR/hook.log"
echo -e "  To uninstall:        bash install.sh --uninstall"
echo ""
