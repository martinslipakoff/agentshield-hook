#!/usr/bin/env python3
"""
AgentShield Hook for Claude Code

Monitors AI agent actions, evaluates risk locally, blocks dangerous operations,
and sends audit events to the AgentShield backend.

Configured in ~/.claude/hooks.json — see install.sh for setup.

Usage:
  PreToolUse:  python3 ~/.agentshield/hook.py pre
  PostToolUse: python3 ~/.agentshield/hook.py post
"""

import json
import sys
import os
import re
import hashlib
import uuid as uuid_mod
from datetime import datetime, timezone
import subprocess
import time

# ── Paths ────────────────────────────────────────────────────────────────────

CONFIG_DIR = os.path.expanduser("~/.agentshield")
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")
RULES_CACHE = os.path.join(CONFIG_DIR, "rules_cache.json")
LOG_FILE = os.path.join(CONFIG_DIR, "hook.log")
RULES_CACHE_TTL = 3600  # 1 hour

# ── Default Security Rules ───────────────────────────────────────────────────
# These are used when the backend is unreachable or rules haven't been synced.
# The backend's security_rules table is the source of truth.

DEFAULT_RULES = [
    {
        "id": "RULE-001",
        "name": "Destructive rm command",
        "category": "filesystem",
        "pattern": r"rm\s+(-rf|--force|--recursive).*(/|~|\$HOME)",
        "severity": "critical",
        "score": 95,
        "enabled": True,
    },
    {
        "id": "RULE-002",
        "name": "SSH/credential access",
        "category": "credentials",
        "pattern": r"(cat|less|head|tail).*(/.ssh/|/.aws/|/.env)",
        "severity": "critical",
        "score": 90,
        "enabled": True,
    },
    {
        "id": "RULE-003",
        "name": "Package install",
        "category": "dependency",
        "pattern": r"(npm install|pip install|cargo add|go get)",
        "severity": "warning",
        "score": 40,
        "enabled": True,
    },
    {
        "id": "RULE-004",
        "name": "Curl to external",
        "category": "network",
        "pattern": r"curl.*https?://",
        "severity": "warning",
        "score": 35,
        "enabled": True,
    },
    {
        "id": "RULE-005",
        "name": "Git push to main",
        "category": "git",
        "pattern": r"git push.*(main|master|prod)",
        "severity": "high",
        "score": 70,
        "enabled": True,
    },
    {
        "id": "RULE-006",
        "name": "Docker privileged",
        "category": "container",
        "pattern": r"docker run.*--privileged",
        "severity": "critical",
        "score": 90,
        "enabled": True,
    },
    {
        "id": "RULE-007",
        "name": "Env variable export",
        "category": "credentials",
        "pattern": r"export.*(API_KEY|SECRET|TOKEN|PASSWORD)",
        "severity": "high",
        "score": 75,
        "enabled": True,
    },
    {
        "id": "RULE-008",
        "name": "Chmod world writable",
        "category": "permissions",
        "pattern": r"chmod.*(777|o\+w)",
        "severity": "high",
        "score": 65,
        "enabled": True,
    },
    {
        "id": "RULE-009",
        "name": "Base64 decode pipe",
        "category": "obfuscation",
        "pattern": r"base64.*-d.*\|",
        "severity": "high",
        "score": 80,
        "enabled": True,
    },
    {
        "id": "RULE-010",
        "name": "Network config change",
        "category": "network",
        "pattern": r"(iptables|ufw|firewall-cmd)",
        "severity": "critical",
        "score": 85,
        "enabled": True,
    },
    {
        "id": "RULE-011",
        "name": "Process kill",
        "category": "system",
        "pattern": r"kill\s+-9",
        "severity": "warning",
        "score": 45,
        "enabled": True,
    },
    {
        "id": "RULE-012",
        "name": "Systemd modification",
        "category": "system",
        "pattern": r"systemctl.*(enable|disable|mask)",
        "severity": "high",
        "score": 70,
        "enabled": True,
    },
    {
        "id": "RULE-013",
        "name": "Cron job modification",
        "category": "persistence",
        "pattern": r"crontab|-e|/etc/cron",
        "severity": "high",
        "score": 75,
        "enabled": True,
    },
    {
        "id": "RULE-014",
        "name": "Download and execute",
        "category": "malware",
        "pattern": r"(wget|curl).*\|.*(sh|bash|python)",
        "severity": "critical",
        "score": 95,
        "enabled": True,
    },
    {
        "id": "RULE-015",
        "name": "Disk/partition ops",
        "category": "filesystem",
        "pattern": r"(fdisk|mkfs|mount|umount)",
        "severity": "critical",
        "score": 85,
        "enabled": True,
    },
    {
        "id": "RULE-016",
        "name": "User/group management",
        "category": "privilege",
        "pattern": r"(useradd|usermod|groupadd|passwd)",
        "severity": "high",
        "score": 70,
        "enabled": True,
    },
    {
        "id": "RULE-017",
        "name": "Sudoers modification",
        "category": "privilege",
        "pattern": r"/etc/sudoers|visudo",
        "severity": "critical",
        "score": 95,
        "enabled": True,
    },
    {
        "id": "RULE-018",
        "name": "File write to /etc",
        "category": "filesystem",
        "pattern": r"(write|create|modify).*/etc/",
        "severity": "high",
        "score": 70,
        "enabled": True,
    },
    {
        "id": "RULE-019",
        "name": "Browser URL access",
        "category": "network",
        "pattern": r"browser.*(http|url|navigate)",
        "severity": "info",
        "score": 20,
        "enabled": True,
    },
    {
        "id": "RULE-020",
        "name": "Large file read",
        "category": "data_exfil",
        "pattern": r"(cat|less|read).*\.(sql|csv|json|db|sqlite)",
        "severity": "warning",
        "score": 50,
        "enabled": True,
    },
]

SEVERITY_RANK = {"info": 0, "warning": 1, "high": 2, "critical": 3}


# ── Logging ──────────────────────────────────────────────────────────────────


def log(msg):
    try:
        with open(LOG_FILE, "a") as f:
            f.write(f"{datetime.now().isoformat()} {msg}\n")
    except Exception:
        pass


# ── Configuration ────────────────────────────────────────────────────────────


def load_config():
    try:
        with open(CONFIG_FILE) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        log(f"Config error: {e}")
        return {}


# ── Rules ────────────────────────────────────────────────────────────────────


def load_rules(config):
    """Load rules from cache (synced from backend) or fall back to defaults."""
    if os.path.exists(RULES_CACHE):
        try:
            with open(RULES_CACHE) as f:
                cache = json.load(f)
            cache_age = time.time() - cache.get("fetched_at", 0)
            rules = cache.get("rules", DEFAULT_RULES)
            # If cache is stale, trigger async refresh
            if cache_age > RULES_CACHE_TTL:
                _refresh_rules_async(config)
            return rules
        except (json.JSONDecodeError, KeyError):
            pass

    # No cache — use defaults and try to sync
    _refresh_rules_async(config)
    return DEFAULT_RULES


def _refresh_rules_async(config):
    """Spawn background process to fetch rules from backend."""
    if not config.get("api_url") or not config.get("collector_key"):
        return
    try:
        subprocess.Popen(
            [sys.executable, os.path.abspath(__file__), "_sync_rules"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except Exception as e:
        log(f"Sync spawn failed: {e}")


def sync_rules():
    """Fetch rules + settings from backend. Runs as background subprocess."""
    config = load_config()
    api_url = config.get("api_url", "")
    key = config.get("collector_key", "")
    if not api_url or not key:
        return

    try:
        from urllib.request import Request, urlopen

        req = Request(
            f"{api_url}/get-collector-config",
            headers={
                "x-collector-key": key,
                "Content-Type": "application/json",
            },
        )
        with urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())

        # Save rules to cache
        cache = {
            "rules": data.get("rules", DEFAULT_RULES),
            "settings": data.get("settings", {}),
            "fetched_at": time.time(),
        }
        with open(RULES_CACHE, "w") as f:
            json.dump(cache, f)

        # Update local settings from server if present
        server_settings = data.get("settings", {})
        if server_settings:
            for key_name in ("mode", "alert_threshold", "block_threshold"):
                if key_name in server_settings:
                    config[key_name] = server_settings[key_name]
            with open(CONFIG_FILE, "w") as f:
                json.dump(config, f, indent=2)

        log("Rules synced from backend")
    except Exception as e:
        log(f"Rule sync failed: {e}")


# ── Config Audit ─────────────────────────────────────────────────────────────

AUDIT_STATE_FILE = os.path.join(CONFIG_DIR, "last_audit.json")
AUDIT_INTERVAL = 86400  # 24 hours


def maybe_audit_config(config):
    """Check if config audit is needed (every 24h or on config change).
    Runs as background subprocess to avoid blocking the hook."""
    try:
        # Read current Claude Code settings
        settings_path = os.path.expanduser("~/.claude/settings.json")
        if not os.path.exists(settings_path):
            return

        with open(settings_path) as f:
            settings_content = f.read()

        # Merge with local settings if exists
        local_path = os.path.expanduser("~/.claude/settings.local.json")
        if os.path.exists(local_path):
            with open(local_path) as f:
                local_content = f.read()
            try:
                merged = json.loads(settings_content)
                merged.update(json.loads(local_content))
                settings_content = json.dumps(merged)
            except json.JSONDecodeError:
                pass

        # Compute hash of current config
        current_hash = hashlib.sha256(settings_content.encode()).hexdigest()

        # Check if audit is needed
        needs_audit = True
        if os.path.exists(AUDIT_STATE_FILE):
            with open(AUDIT_STATE_FILE) as f:
                state = json.load(f)
            last_time = state.get("timestamp", 0)
            last_hash = state.get("config_hash", "")
            if current_hash == last_hash and (time.time() - last_time) < AUDIT_INTERVAL:
                needs_audit = False

        if not needs_audit:
            return

        # Spawn background audit
        subprocess.Popen(
            [sys.executable, os.path.abspath(__file__), "_audit_config"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except Exception as e:
        log(f"Audit check failed: {e}")


def run_audit():
    """Send config snapshot to backend for security analysis. Background subprocess."""
    config = load_config()
    api_url = config.get("api_url", "")
    key = config.get("collector_key", "")
    if not api_url or not key:
        return

    try:
        from urllib.request import Request, urlopen

        settings_path = os.path.expanduser("~/.claude/settings.json")
        if not os.path.exists(settings_path):
            return

        with open(settings_path) as f:
            snapshot = json.load(f)

        # Merge local settings
        local_path = os.path.expanduser("~/.claude/settings.local.json")
        if os.path.exists(local_path):
            try:
                with open(local_path) as f:
                    snapshot.update(json.load(f))
            except (json.JSONDecodeError, Exception):
                pass

        # Strip sensitive values — only send structure, not secrets
        # Remove webhook URLs, tokens, keys from the snapshot
        sanitized = json.loads(json.dumps(snapshot))
        for k in list(sanitized.keys()):
            if "key" in k.lower() or "token" in k.lower() or "secret" in k.lower():
                sanitized[k] = "[REDACTED]"

        payload = json.dumps({
            "config_snapshot": sanitized,
            "collector_key": key,
            "machine_name": config.get("machine_name", "unknown"),
        }).encode()

        req = Request(
            f"{api_url}/audit-config",
            data=payload,
            headers={
                "x-collector-key": key,
                "Content-Type": "application/json",
            },
            method="POST",
        )
        with urlopen(req, timeout=10) as resp:
            resp.read()

        # Update audit state
        config_hash = hashlib.sha256(
            open(settings_path).read().encode()
        ).hexdigest()
        with open(AUDIT_STATE_FILE, "w") as f:
            json.dump({"timestamp": time.time(), "config_hash": config_hash}, f)

        log("Config audit sent")
    except Exception as e:
        log(f"Config audit failed: {e}")


# ── Command Extraction ───────────────────────────────────────────────────────


def extract_command(tool_name, tool_input):
    """Build a string from tool input that security rules can match against."""
    tn = (tool_name or "").lower()

    if tn == "bash":
        return tool_input.get("command", "")
    elif tn in ("write", "edit"):
        path = tool_input.get("file_path", tool_input.get("path", ""))
        return f"write {path}"
    elif tn == "read":
        path = tool_input.get("file_path", tool_input.get("path", ""))
        return f"read {path}"
    elif tn in ("glob", "grep"):
        return f"{tn} {tool_input.get('pattern', '')}"
    elif tn in ("webfetch", "web_fetch"):
        return f"browser navigate {tool_input.get('url', '')}"
    elif tn in ("websearch", "web_search"):
        return f"browser search {tool_input.get('query', '')}"
    elif tn == "agent":
        return f"agent {tool_input.get('prompt', '')[:200]}"
    else:
        vals = " ".join(str(v)[:100] for v in tool_input.values() if v)
        return f"{tn} {vals}"[:500]


# ── Rule Evaluation ──────────────────────────────────────────────────────────


def evaluate_rules(command, rules):
    """Match command against all enabled rules. Returns (triggered_ids, max_score, max_severity)."""
    triggered = []
    max_score = 0
    max_severity = "info"

    for rule in rules:
        if not rule.get("enabled", True):
            continue
        try:
            if re.search(rule["pattern"], command, re.IGNORECASE):
                triggered.append(rule["id"])
                score = rule.get("score", 0)
                if score > max_score:
                    max_score = score
                sev = rule.get("severity", "info")
                if SEVERITY_RANK.get(sev, 0) > SEVERITY_RANK.get(max_severity, 0):
                    max_severity = sev
        except re.error:
            continue

    return triggered, max_score, max_severity


# ── Event Sending ────────────────────────────────────────────────────────────


def send_event(event, config):
    """POST event to backend in a background process (non-blocking)."""
    api_url = config.get("api_url")
    key = config.get("collector_key")
    if not api_url or not key:
        log("No API URL or key — event not sent")
        return

    payload = json.dumps([event])
    try:
        subprocess.Popen(
            [
                "curl",
                "-s",
                "-o",
                "/dev/null",
                "-X",
                "POST",
                f"{api_url}/ingest-events",
                "-H",
                "Content-Type: application/json",
                "-H",
                f"x-collector-key: {key}",
                "-d",
                payload,
                "--max-time",
                "10",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except Exception as e:
        log(f"Event send failed: {e}")


# ── Helpers ──────────────────────────────────────────────────────────────────


def detect_project():
    """Walk up from cwd to find a .git directory; return that folder's name."""
    cwd = os.getcwd()
    d = cwd
    while d != os.path.dirname(d):
        if os.path.isdir(os.path.join(d, ".git")):
            return os.path.basename(d)
        d = os.path.dirname(d)
    return os.path.basename(cwd)


# ── Main ─────────────────────────────────────────────────────────────────────


def main():
    # Internal commands (called as background subprocesses)
    if len(sys.argv) > 1 and sys.argv[1] == "_sync_rules":
        sync_rules()
        return
    if len(sys.argv) > 1 and sys.argv[1] == "_audit_config":
        run_audit()
        return

    hook_type = sys.argv[1] if len(sys.argv) > 1 else "pre"

    # Read JSON from Claude Code via stdin
    try:
        raw_input = sys.stdin.read()
        log(f"stdin raw ({len(raw_input)} bytes): {raw_input[:500]}")
        if not raw_input.strip():
            log("stdin is empty — exiting")
            sys.exit(0)
        input_data = json.loads(raw_input)
    except (json.JSONDecodeError, Exception) as e:
        log(f"stdin parse error: {e}")
        sys.exit(0)  # Don't block on parse errors

    config = load_config()
    if not config:
        # Not initialized — allow everything
        sys.exit(0)

    # Config audit (background, non-blocking, every 24h or on change)
    if hook_type == "pre":
        maybe_audit_config(config)

    rules = load_rules(config)

    tool_name = input_data.get("tool_name", "unknown")
    tool_input = input_data.get("tool_input", {})
    session_id = input_data.get("session_id", f"ses-{uuid_mod.uuid4()}")

    # Build command string for rule matching
    command = extract_command(tool_name, tool_input)

    # Evaluate rules
    triggered, risk_score, severity = evaluate_rules(command, rules)

    # Check allowlists — if command matches, override to safe
    for allowed in config.get("allowlist_commands", []):
        if allowed and allowed in command:
            triggered, risk_score, severity = [], 0, "info"
            break

    # Determine if we should block (only on PreToolUse in block mode)
    blocked = False
    block_reason = ""
    mode = config.get("mode", "block")

    if hook_type == "pre" and mode == "block":
        if risk_score >= config.get("block_threshold", 80):
            blocked = True
            rule_id = triggered[0] if triggered else "UNKNOWN"
            rule_name = next(
                (r.get("name", rule_id) for r in rules if r["id"] == rule_id),
                rule_id,
            )
            block_reason = f"Rule {rule_id}: {rule_name}"

    # Build event payload
    event = {
        "id": f"evt-{uuid_mod.uuid4()}",
        "session_id": session_id,
        "tool": tool_name.lower(),
        "command": command[:2000],
        "hash": "",
        "previous_hash": "genesis",
        "signature": "",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "agent": config.get("default_agent", "claude"),
        "machine": config.get("machine_name", "unknown"),
        "project": detect_project(),
        "event_type": f"{'pre' if hook_type == 'pre' else 'post'}_tool_use",
        "severity": severity,
        "risk_score": risk_score,
        "blocked": blocked,
        "block_reason": block_reason or None,
        "triggered_rules": triggered,
        "cwd": os.getcwd(),
        "source": "hook",
    }

    # Add file metadata for file operations
    if tool_name.lower() in ("write", "edit", "read"):
        event["file_path"] = tool_input.get(
            "file_path", tool_input.get("path", "")
        )
        event["file_operation"] = (
            "read" if tool_name.lower() == "read" else "write"
        )

    # Send event to backend (background, non-blocking)
    send_event(event, config)

    log(
        f"{hook_type} | {tool_name} | risk={risk_score} | "
        f"blocked={blocked} | {command[:80]}"
    )

    # ── Response to Claude Code ──────────────────────────────────────────

    if blocked:
        # Block: output reason to stderr, exit non-zero
        print(
            f"AgentShield BLOCKED: {block_reason} (risk: {risk_score}/100)",
            file=sys.stderr,
        )
        sys.exit(2)

    if (
        risk_score >= config.get("alert_threshold", 60)
        and hook_type == "pre"
    ):
        # Warn but allow
        print(
            f"AgentShield WARNING: risk {risk_score}/100 "
            f"({', '.join(triggered)})",
            file=sys.stderr,
        )

    sys.exit(0)


if __name__ == "__main__":
    main()
