#!/bin/bash
set -euo pipefail

AIRLOCK_DIR="$(cd "$(dirname "$0")" && pwd)"
HOOK_DST="$HOME/.config/airlock/hook.sh"
BIN="/usr/local/bin/airlock"
OS="$(uname -s)"

FILES=(
    "$AIRLOCK_DIR/airlock.py"
    "$AIRLOCK_DIR/auditor.py"
    "$AIRLOCK_DIR/ai_shield.py"
    "$AIRLOCK_DIR/netwatch.py"
    "$AIRLOCK_DIR/airlock-hook.sh"
    "$HOOK_DST"
    "$BIN"
)

_lock() {
    local f="$1"
    [ -f "$f" ] || return 0
    if [ "$OS" = "Darwin" ]; then
        sudo chflags uchg "$f" 2>/dev/null && echo "  Locked:   $f" || echo "  Skip:     $f"
    else
        sudo chattr +i "$f" 2>/dev/null && echo "  Locked:   $f" || echo "  Skip:     $f"
    fi
}

_unlock() {
    local f="$1"
    [ -f "$f" ] || return 0
    if [ "$OS" = "Darwin" ]; then
        sudo chflags nouchg "$f" 2>/dev/null && echo "  Unlocked: $f" || echo "  Skip:     $f"
    else
        sudo chattr -i "$f" 2>/dev/null && echo "  Unlocked: $f" || echo "  Skip:     $f"
    fi
}

case "${1:-}" in
    lock)
        echo "Locking airlock files..."
        for f in "${FILES[@]}"; do _lock "$f"; done
        echo "Done."
        ;;
    unlock)
        echo "Unlocking airlock files..."
        for f in "${FILES[@]}"; do _unlock "$f"; done
        echo "Done."
        ;;
    *)
        echo "Usage: $0 <lock|unlock>"
        echo ""
        echo "  lock    — make airlock files immutable (prevents tampering)"
        echo "  unlock  — remove immutable flag (allows editing/reinstall)"
        exit 1
        ;;
esac
