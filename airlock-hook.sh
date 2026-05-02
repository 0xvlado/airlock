# airlock-hook.sh — source from .bashrc / .zshrc / .bash_profile
# Intercepts package install commands and routes through airlock
#
# Bypass a single command:  AIRLOCK_BYPASS=1 npm install <pkg>
# Disable entirely:         export AIRLOCK_DISABLED=1
# Use real binary directly: command npm install <pkg>

_airlock_intercept() {
    local pm="$1"
    shift

    if [ -z "${npm_lifecycle_event:-}" ]; then
        if [ "${AIRLOCK_DISABLED:-0}" = "1" ] || [ "${AIRLOCK_BYPASS:-0}" = "1" ]; then
            command "$pm" "$@"
            return
        fi
    fi

    if ! command -v airlock >/dev/null 2>&1; then
        command "$pm" "$@"
        return
    fi

    local subcmd="${1:-}"
    case "$subcmd" in
        install|i|add)
            shift
            printf '\033[0;36m[airlock]\033[0m intercepting %s %s\n' "$pm" "$subcmd"
            command airlock install --pm "$pm" -- "$@"
            ;;
        update|upgrade|up)
            shift
            printf '\033[0;36m[airlock]\033[0m intercepting %s %s\n' "$pm" "$subcmd"
            command airlock install --pm "$pm" --subcmd update -- "$@"
            ;;
        dlx|exec)
            shift
            printf '\033[0;36m[airlock]\033[0m intercepting %s %s\n' "$pm" "$subcmd"
            command airlock exec -- "$pm" "$subcmd" "$@"
            ;;
        *)
            command "$pm" "$@"
            ;;
    esac
}

_airlock_exec_intercept() {
    local runner="$1"
    shift

    if [ -z "${npm_lifecycle_event:-}" ]; then
        if [ "${AIRLOCK_DISABLED:-0}" = "1" ] || [ "${AIRLOCK_BYPASS:-0}" = "1" ]; then
            command "$runner" "$@"
            return
        fi
    fi

    if ! command -v airlock >/dev/null 2>&1; then
        command "$runner" "$@"
        return
    fi

    printf '\033[0;36m[airlock]\033[0m intercepting %s\n' "$runner"
    command airlock exec -- "$runner" "$@"
}

npm()  { _airlock_intercept npm  "$@"; }
pnpm() { _airlock_intercept pnpm "$@"; }
yarn() { _airlock_intercept yarn "$@"; }
bun()  { _airlock_intercept bun  "$@"; }
npx()  { _airlock_exec_intercept npx  "$@"; }
bunx() { _airlock_exec_intercept bunx "$@"; }
