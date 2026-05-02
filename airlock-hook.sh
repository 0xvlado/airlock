# airlock-hook.sh — source from .bashrc / .zshrc / .bash_profile
# Intercepts package install commands and routes through airlock
#
# Bypass a single command:  AIRLOCK_BYPASS=1 npm install <pkg>
# Disable entirely:         export AIRLOCK_DISABLED=1
# Use real binary directly: command npm install <pkg>

_airlock_intercept() {
    local pm="$1"
    shift

    if [ "${AIRLOCK_DISABLED:-0}" = "1" ] || [ "${AIRLOCK_BYPASS:-0}" = "1" ]; then
        command "$pm" "$@"
        return
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
        *)
            command "$pm" "$@"
            ;;
    esac
}

npm()  { _airlock_intercept npm  "$@"; }
pnpm() { _airlock_intercept pnpm "$@"; }
yarn() { _airlock_intercept yarn "$@"; }
bun()  { _airlock_intercept bun  "$@"; }
