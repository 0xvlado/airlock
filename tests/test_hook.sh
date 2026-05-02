#!/bin/bash
# Tests for airlock-hook.sh bypass/lifecycle behavior
# Run: bash tests/test_hook.sh
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
HOOK="$SCRIPT_DIR/../airlock-hook.sh"
PASS=0
FAIL=0

_assert_eq() {
    local desc="$1" expected="$2" actual="$3"
    if [ "$expected" = "$actual" ]; then
        printf "  PASS: %s\n" "$desc"
        PASS=$((PASS + 1))
    else
        printf "  FAIL: %s (expected '%s', got '%s')\n" "$desc" "$expected" "$actual"
        FAIL=$((FAIL + 1))
    fi
}

_assert_contains() {
    local desc="$1" expected="$2" actual="$3"
    if echo "$actual" | grep -qF "$expected"; then
        printf "  PASS: %s\n" "$desc"
        PASS=$((PASS + 1))
    else
        printf "  FAIL: %s (expected to contain '%s', got '%s')\n" "$desc" "$expected" "$actual"
        FAIL=$((FAIL + 1))
    fi
}

_assert_not_contains() {
    local desc="$1" unexpected="$2" actual="$3"
    if echo "$actual" | grep -qF "$unexpected"; then
        printf "  FAIL: %s (should not contain '%s', got '%s')\n" "$desc" "$unexpected" "$actual"
        FAIL=$((FAIL + 1))
    else
        printf "  PASS: %s\n" "$desc"
        PASS=$((PASS + 1))
    fi
}

# We create a fake airlock binary that just prints "AIRLOCK_CALLED"
# and a fake npm that prints "NPM_CALLED" so we can detect which path was taken.
TMPBIN="$(mktemp -d)"
cat > "$TMPBIN/airlock" << 'EOF'
#!/bin/bash
echo "AIRLOCK_CALLED"
EOF
chmod +x "$TMPBIN/airlock"

cat > "$TMPBIN/npm_real" << 'EOF'
#!/bin/bash
echo "NPM_CALLED"
EOF
chmod +x "$TMPBIN/npm_real"

cat > "$TMPBIN/npx_real" << 'EOF'
#!/bin/bash
echo "NPX_CALLED"
EOF
chmod +x "$TMPBIN/npx_real"

# Override command lookup so the hook finds our fakes
export PATH="$TMPBIN:$PATH"

# --- Test helper: run a snippet in a subshell with the hook sourced ---
_run_hook_test() {
    local env_setup="$1"
    local cmd="$2"
    # We need 'command npm' to resolve to our fake npm_real,
    # so alias the real binaries
    bash -c "
        # Make 'command npm' find our fake
        ln -sf '$TMPBIN/npm_real' '$TMPBIN/npm' 2>/dev/null
        ln -sf '$TMPBIN/npx_real' '$TMPBIN/npx' 2>/dev/null
        export PATH='$TMPBIN:\$PATH'
        $env_setup
        source '$HOOK'
        $cmd 2>/dev/null
    " 2>/dev/null
}

echo "=== Bypass tests ==="

# Normal bypass (no lifecycle) — should go to real npm
out="$(_run_hook_test "export AIRLOCK_BYPASS=1; unset npm_lifecycle_event" "npm install foo")"
_assert_contains "AIRLOCK_BYPASS=1 without lifecycle bypasses airlock" "NPM_CALLED" "$out"
_assert_not_contains "AIRLOCK_BYPASS=1 without lifecycle skips airlock" "AIRLOCK_CALLED" "$out"

# Normal disable (no lifecycle) — should go to real npm
out="$(_run_hook_test "export AIRLOCK_DISABLED=1; unset npm_lifecycle_event" "npm install foo")"
_assert_contains "AIRLOCK_DISABLED=1 without lifecycle bypasses airlock" "NPM_CALLED" "$out"
_assert_not_contains "AIRLOCK_DISABLED=1 without lifecycle skips airlock" "AIRLOCK_CALLED" "$out"

# Bypass INSIDE lifecycle — should NOT bypass, should go to airlock
out="$(_run_hook_test "export AIRLOCK_BYPASS=1; export npm_lifecycle_event=postinstall" "npm install foo")"
_assert_contains "AIRLOCK_BYPASS=1 inside lifecycle still routes to airlock" "AIRLOCK_CALLED" "$out"
_assert_not_contains "AIRLOCK_BYPASS=1 inside lifecycle does not pass through" "NPM_CALLED" "$out"

# Disable INSIDE lifecycle — should NOT bypass, should go to airlock
out="$(_run_hook_test "export AIRLOCK_DISABLED=1; export npm_lifecycle_event=postinstall" "npm install foo")"
_assert_contains "AIRLOCK_DISABLED=1 inside lifecycle still routes to airlock" "AIRLOCK_CALLED" "$out"
_assert_not_contains "AIRLOCK_DISABLED=1 inside lifecycle does not pass through" "NPM_CALLED" "$out"

# Both flags INSIDE lifecycle — should NOT bypass
out="$(_run_hook_test "export AIRLOCK_BYPASS=1; export AIRLOCK_DISABLED=1; export npm_lifecycle_event=install" "npm install foo")"
_assert_contains "Both flags inside lifecycle still routes to airlock" "AIRLOCK_CALLED" "$out"
_assert_not_contains "Both flags inside lifecycle does not pass through" "NPM_CALLED" "$out"

echo ""
echo "=== Exec bypass tests ==="

# npx bypass without lifecycle — should go to real npx
out="$(_run_hook_test "export AIRLOCK_BYPASS=1; unset npm_lifecycle_event" "npx cowsay hello")"
_assert_contains "npx AIRLOCK_BYPASS=1 without lifecycle bypasses airlock" "NPX_CALLED" "$out"
_assert_not_contains "npx AIRLOCK_BYPASS=1 without lifecycle skips airlock" "AIRLOCK_CALLED" "$out"

# npx bypass INSIDE lifecycle — should go to airlock
out="$(_run_hook_test "export AIRLOCK_BYPASS=1; export npm_lifecycle_event=postinstall" "npx cowsay hello")"
_assert_contains "npx AIRLOCK_BYPASS=1 inside lifecycle still routes to airlock" "AIRLOCK_CALLED" "$out"
_assert_not_contains "npx AIRLOCK_BYPASS=1 inside lifecycle does not pass through" "NPX_CALLED" "$out"

echo ""
echo "=== Interception tests ==="

# Normal install (no bypass, no lifecycle) — should go to airlock
out="$(_run_hook_test "unset AIRLOCK_BYPASS; unset AIRLOCK_DISABLED; unset npm_lifecycle_event" "npm install foo")"
_assert_contains "Normal npm install routes to airlock" "AIRLOCK_CALLED" "$out"

# Non-install command — should pass through to real npm
out="$(_run_hook_test "unset AIRLOCK_BYPASS; unset AIRLOCK_DISABLED; unset npm_lifecycle_event" "npm run build")"
_assert_contains "npm run build passes through" "NPM_CALLED" "$out"
_assert_not_contains "npm run build skips airlock" "AIRLOCK_CALLED" "$out"

# Update command — should go to airlock
out="$(_run_hook_test "unset AIRLOCK_BYPASS; unset AIRLOCK_DISABLED; unset npm_lifecycle_event" "npm update")"
_assert_contains "npm update routes to airlock" "AIRLOCK_CALLED" "$out"

echo ""
echo "=== Results ==="
echo "  Passed: $PASS"
echo "  Failed: $FAIL"

rm -rf "$TMPBIN"

[ "$FAIL" -eq 0 ]
