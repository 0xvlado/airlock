#!/bin/bash
set -euo pipefail

AIRLOCK_DIR="$(cd "$(dirname "$0")" && pwd)"
HOOK_SRC="$AIRLOCK_DIR/airlock-hook.sh"
HOOK_DIR="$HOME/.config/airlock"
HOOK_DST="$HOOK_DIR/hook.sh"
SOURCE_LINE="[ -f \"$HOME/.config/airlock/hook.sh\" ] && source \"$HOME/.config/airlock/hook.sh\""

OS="$(uname -s)"

echo "=== airlock setup ($OS) ==="
echo ""

# --- Step 1: Find python3 ---
echo "[1/5] Checking python3..."
if command -v python3 >/dev/null 2>&1; then
    PYTHON3="$(command -v python3)"
    echo "  Found: $PYTHON3"
else
    echo "  ERROR: python3 not found. Install Python 3 first."
    exit 1
fi

# --- Step 2: Install airlock CLI ---
echo "[2/5] Installing airlock CLI..."

if [ "$OS" = "Darwin" ]; then
    BIN_DIR="/usr/local/bin"
    [ -d "$BIN_DIR" ] || sudo mkdir -p "$BIN_DIR"
else
    BIN_DIR="/usr/local/bin"
fi

sudo tee "$BIN_DIR/airlock" > /dev/null << EOF
#!/bin/bash
exec "$PYTHON3" "$AIRLOCK_DIR/airlock.py" "\$@"
EOF
sudo chmod +x "$BIN_DIR/airlock"
echo "  Installed: $BIN_DIR/airlock"

# --- Step 3: Install shell hook ---
echo "[3/5] Installing shell hook..."
mkdir -p "$HOOK_DIR"
cp "$HOOK_SRC" "$HOOK_DST"
chmod 644 "$HOOK_DST"
echo "  Installed: $HOOK_DST"

# --- Step 3b: Detect plugins ---
echo "  Detecting plugins..."
PLUGINS_DST="$HOOK_DIR/plugins.json"

if [ ! -f "$PLUGINS_DST" ]; then
    # Check for aikido safe-chain
    if command -v safe-chain >/dev/null 2>&1; then
        echo "  Detected: aikido safe-chain"
        cat > "$PLUGINS_DST" << 'PLUGEOF'
{
  "plugins": [
    {
      "name": "aikido",
      "phase": "install_binary",
      "command": "safe-chain",
      "mode": "prefix",
      "blocking": true,
      "enabled": true
    }
  ]
}
PLUGEOF
        echo "  Created:  $PLUGINS_DST (aikido enabled)"
    else
        echo "  No external security plugins detected"
        echo "  Tip: Install aikido safe-chain for additional malware scanning"
        echo "        curl -fsSL https://github.com/AikidoSec/safe-chain/releases/latest/download/install-safe-chain.sh | sh"
    fi
else
    echo "  Existing: $PLUGINS_DST (kept as-is)"
fi

# --- Step 4: Add to shell rc files ---
echo "[4/5] Configuring shell startup..."

_add_to_rc() {
    local rc="$1"
    if [ -f "$rc" ]; then
        if grep -qF "airlock/hook.sh" "$rc" 2>/dev/null; then
            echo "  Already in: $rc"
        else
            printf '\n# airlock: intercept package installs\n%s\n' "$SOURCE_LINE" >> "$rc"
            echo "  Added to:   $rc"
        fi
    fi
}

_create_rc_with_hook() {
    local rc="$1"
    printf '# airlock: intercept package installs\n%s\n' "$SOURCE_LINE" > "$rc"
    echo "  Created:    $rc"
}

FOUND_RC=0

if [ -f "$HOME/.zshrc" ]; then
    _add_to_rc "$HOME/.zshrc"
    FOUND_RC=1
fi

if [ -f "$HOME/.bashrc" ]; then
    _add_to_rc "$HOME/.bashrc"
    FOUND_RC=1
fi

if [ -f "$HOME/.bash_profile" ]; then
    _add_to_rc "$HOME/.bash_profile"
    FOUND_RC=1
fi

if [ "$FOUND_RC" = "0" ]; then
    if [ "$OS" = "Darwin" ]; then
        _create_rc_with_hook "$HOME/.zshrc"
    else
        _create_rc_with_hook "$HOME/.bashrc"
    fi
fi

# --- Step 5: Lock files against tampering ---
echo "[5/5] Locking files (immutable)..."

_lock_file() {
    local f="$1"
    if [ "$OS" = "Darwin" ]; then
        sudo chflags uchg "$f" 2>/dev/null && echo "  Locked: $f" || echo "  Skip:  $f (chflags failed)"
    else
        sudo chattr +i "$f" 2>/dev/null && echo "  Locked: $f" || echo "  Skip:  $f (chattr failed)"
    fi
}

_lock_file "$AIRLOCK_DIR/airlock.py"
_lock_file "$AIRLOCK_DIR/auditor.py"
_lock_file "$AIRLOCK_DIR/ai_shield.py"
_lock_file "$AIRLOCK_DIR/netwatch.py"
_lock_file "$AIRLOCK_DIR/airlock-hook.sh"
_lock_file "$HOOK_DST"
_lock_file "$BIN_DIR/airlock"

echo ""
echo "=== Setup complete ==="
echo ""
echo "Restart your shell or run:"
echo "  source $HOOK_DST"
echo ""
echo "Usage:"
echo "  npm install <pkg>    # automatically intercepted"
echo "  pnpm add <pkg>       # automatically intercepted"
echo "  yarn add <pkg>       # automatically intercepted"
echo "  bun add <pkg>        # automatically intercepted"
echo ""
echo "Bypass:"
echo "  AIRLOCK_BYPASS=1 npm install <pkg>   # skip for one command"
echo "  export AIRLOCK_DISABLED=1            # disable entirely"
echo "  command npm install <pkg>            # use real binary directly"
echo ""
if [ "$OS" = "Darwin" ]; then
    echo "Note: On macOS, post-install script sandboxing (Phase 4) is not"
    echo "available. Phases 1-3 (audit, safe install, AI scan) work fully."
fi
