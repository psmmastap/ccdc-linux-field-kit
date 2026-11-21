#!/bin/sh
# Standalone CCDC Linux tool-readiness checker and opt-in installer.
# POSIX sh: works before Python/Bash are installed. No other toolkit file needed.
# Default is CHECK/PLAN ONLY. Does not scan, capture traffic, hunt or change accounts.
set -u
set -f
umask 077
# Admin utilities may be installed in sbin but absent from a normal user's PATH.
PATH=${PATH:-/usr/bin:/bin}:/usr/sbin:/sbin
export PATH

usage() {
    printf '%s\n' 'Usage: sh prepare_box.sh [options]' \
      '  --profile LIST    core (default); add network,backup,triage,firewall or all' \
      '                    Example: --profile core,network,backup' \
      '  --plan            Explicit check/plan only (the default)' \
      '  --install         Install missing tool packages; requires --approved and root' \
      '  --approved        Confirm officials/owner authorized these package changes' \
      '  --refresh         Refresh repository metadata before install (not on Arch)' \
      '  --allow-firewall-packages  Also acknowledge firewall package/backend side effects' \
      '  --output DIR      Save a private text report inside DIR (on assigned host only)' \
      '  --os-release FILE Inspect an OS fixture; check/plan only, never install' \
      '  --help            Show this help' \
      '' \
      'Supports package plans for Debian/Ubuntu, RHEL/Fedora, SUSE, Arch and Alpine.' \
      'Gentoo, Slackware, NixOS, immutable and unknown systems: manual provisioning.' \
      'Presence/version checks are NOT proof a box is secure or services are healthy.' \
      'Install scripts/triggers/dependencies can change a box. Snapshot and review first.' \
      '' \
      'TRYOUT RULES: no hunting/removal before noon; keep whiteteam unchanged;' \
      'honor supplied whitelists; do not export competition technical information.' \
      'AI tools are prohibited during the event. Obtain approval for prewritten scripts.' \
      'Exit: 0=selected checks pass; 1=missing capabilities; 2=refused/usage; 3=package failure.'
}

fail() { printf 'ERROR: %s\n' "$*" >&2; exit 2; }
need_value() { [ "$#" -ge 2 ] && [ -n "$2" ] || fail "missing value for $1"; }

PROFILES=core
INSTALL=no
APPROVED=no
REFRESH=no
FIREWALL_OK=no
EXPLICIT_PLAN=no
OUTPUT=
OS_FILE=/etc/os-release
CUSTOM_OS=no
while [ "$#" -gt 0 ]; do
    case "$1" in
        --help|-h) usage; exit 0 ;;
        --profile) need_value "$@"; PROFILES=$2; shift 2 ;;
        --plan) EXPLICIT_PLAN=yes; shift ;;
        --install) INSTALL=yes; shift ;;
        --approved) APPROVED=yes; shift ;;
        --refresh) REFRESH=yes; shift ;;
        --allow-firewall-packages) FIREWALL_OK=yes; shift ;;
        --output) need_value "$@"; OUTPUT=$2; shift 2 ;;
        --os-release) need_value "$@"; OS_FILE=$2; CUSTOM_OS=yes; shift 2 ;;
        *) fail "unknown option: $1" ;;
    esac
done
[ "$INSTALL:$EXPLICIT_PLAN" != yes:yes ] || fail '--plan and --install cannot be combined'
[ "$REFRESH:$INSTALL" != yes:no ] || fail '--refresh requires --install'
[ "$INSTALL:$APPROVED" != yes:no ] || fail '--install requires --approved; default mode changes nothing'
[ "$INSTALL:$CUSTOM_OS" != yes:yes ] || fail '--os-release fixtures are check/plan only'

# Never source os-release: it is data, not a shell program.
OS_ID=unknown
OS_LIKE=
OS_NAME=unknown
OS_VERSION=unknown
if [ ! -r "$OS_FILE" ] && [ "$CUSTOM_OS" = no ]; then OS_FILE=/usr/lib/os-release; fi
if [ -r "$OS_FILE" ]; then
    while IFS='=' read -r key value || [ -n "$key" ]; do
        case "$value" in
            \"*\") value=${value#\"}; value=${value%\"} ;;
            \'*\') value=${value#\'}; value=${value%\'} ;;
        esac
        case "$key" in
            ID) OS_ID=$value ;;
            ID_LIKE) OS_LIKE=$value ;;
            PRETTY_NAME) OS_NAME=$value ;;
            VERSION_ID) OS_VERSION=$value ;;
        esac
    done < "$OS_FILE"
fi

FAMILY=unknown
# Prefer exact ID; ID_LIKE is only a fallback. Expand only with globbing disabled.
for candidate in "$OS_ID" $OS_LIKE; do
    case "$candidate" in
        debian|ubuntu|linuxmint|kali|pop|raspbian|neon) FAMILY=debian ;;
        rhel|fedora|centos|rocky|almalinux|ol|amzn|redhat|scientific) FAMILY=rpm ;;
        opensuse*|suse|sles|sled) FAMILY=suse ;;
        arch|manjaro|endeavouros) FAMILY=arch ;;
        alpine) FAMILY=alpine ;;
        gentoo) FAMILY=gentoo ;;
        slackware) FAMILY=slackware ;;
        nixos) FAMILY=nixos ;;
        *) continue ;;
    esac
    break
done
MANAGER=manual
case "$FAMILY" in
    debian) MANAGER=apt-get ;;
    rpm) if command -v dnf >/dev/null 2>&1; then MANAGER=dnf; else MANAGER=yum; fi ;;
    suse) MANAGER=zypper ;;
    arch) MANAGER=pacman ;;
    alpine) MANAGER=apk ;;
esac
IMMUTABLE=no
if [ -e /run/ostree-booted ] || command -v transactional-update >/dev/null 2>&1; then IMMUTABLE=yes; fi
case "$OS_ID" in silverblue|coreos|fedora-coreos|flatcar|bottlerocket|talos|opensuse-microos|sle-micro|opensuse-aeon|opensuse-kalpa|microos|aeon|kalpa) IMMUTABLE=yes ;; esac

# Core is always included. Other profiles add tools, never start their functions.
CHECKS='python3 bash ip ss ps find tar gzip sha256sum timeout curl openssl ssh awk grep sed df free less tmux ca_bundle'
OLD_IFS=$IFS
IFS=,
set -- $PROFILES
IFS=$OLD_IFS
[ "$#" -gt 0 ] || fail 'empty profile list'
for profile in "$@"; do
    case "$profile" in
        core) ;;
        network) CHECKS="$CHECKS dig tcpdump lsof nc traceroute nmap" ;;
        backup) CHECKS="$CHECKS getfacl getfattr rsync" ;;
        triage) CHECKS="$CHECKS lsof strace getcap lsattr file" ;;
        firewall) CHECKS="$CHECKS iptables-save ip6tables-save nft" ;;
        all) CHECKS="$CHECKS dig tcpdump lsof nc traceroute nmap getfacl getfattr rsync strace getcap lsattr file iptables-save ip6tables-save nft" ;;
        *) fail "unknown profile: $profile" ;;
    esac
done

if [ "$INSTALL" = yes ]; then
    [ "$CUSTOM_OS" = no ] || fail 'cannot install with an OS fixture'
    [ "$(uname -s)" = Linux ] || fail 'installation supported only on Linux'
    [ "$(id -u)" = 0 ] || fail 'installation requires root; review the plan before using sudo'
    [ "$IMMUTABLE" = no ] || fail 'immutable/transactional host detected; use its native provisioning model'
    [ "$MANAGER" != manual ] || fail "no automatic installer for $FAMILY; see docs/DISTROS.md"
    command -v "$MANAGER" >/dev/null 2>&1 || fail "package manager missing: $MANAGER"
    [ "$FAMILY:$REFRESH" != arch:yes ] || fail 'no pacman -Sy: partial updates are unsafe; provision Arch in a lab with its supported full-update workflow'
    case " $CHECKS " in
        *' iptables-save '*) [ "$FIREWALL_OK" = yes ] || fail 'firewall profile installation also requires --allow-firewall-packages' ;;
    esac
fi

REPORT=
if [ -n "$OUTPUT" ]; then
    case "$OUTPUT" in /*) ;; *) OUTPUT=./$OUTPUT ;; esac
    mkdir -p "$OUTPUT" || fail "cannot create output parent: $OUTPUT"
    RUN_DIR=$(mktemp -d "$OUTPUT/readiness.XXXXXX") || fail 'cannot create private report directory'
    chmod 700 "$RUN_DIR" || fail 'cannot restrict report directory'
    REPORT=$RUN_DIR/report.txt
    printf 'Report stays on this host: %s\n' "$REPORT"
    exec 3>&1
    exec > "$REPORT" 2>&1
fi

package_for() {
    tool=$1
    case "$FAMILY" in debian|rpm|suse|arch|alpine) ;; *) printf '%s\n' MANUAL; return ;; esac
    case "$tool" in
        python3) case "$FAMILY" in arch) printf '%s\n' python ;; *) printf '%s\n' python3 ;; esac ;;
        ip|ss)
            case "$FAMILY:$tool" in rpm:*) printf '%s\n' iproute ;; alpine:ss) printf '%s\n' iproute2-ss ;; *) printf '%s\n' iproute2 ;; esac ;;
        ps|free)
            case "$FAMILY" in rpm|arch|alpine) printf '%s\n' procps-ng ;; *) printf '%s\n' procps ;; esac ;;
        find) printf '%s\n' findutils ;;
        sha256sum|timeout|df) printf '%s\n' coreutils ;;
        ssh)
            case "$FAMILY" in debian) printf '%s\n' openssh-client ;; rpm|suse) printf '%s\n' openssh-clients ;; alpine) printf '%s\n' openssh-client-default ;; arch) printf '%s\n' openssh ;; esac ;;
        ca_bundle) printf '%s\n' ca-certificates ;;
        dig)
            case "$FAMILY" in debian) printf '%s\n' dnsutils ;; rpm|suse) printf '%s\n' bind-utils ;; arch) printf '%s\n' bind ;; alpine) printf '%s\n' bind-tools ;; esac ;;
        nc)
            case "$FAMILY" in debian|suse|alpine) printf '%s\n' netcat-openbsd ;; rpm) printf '%s\n' nmap-ncat ;; arch) printf '%s\n' openbsd-netcat ;; esac ;;
        getfacl) printf '%s\n' acl ;;
        getfattr) printf '%s\n' attr ;;
        getcap)
            case "$FAMILY" in debian) printf '%s\n' libcap2-bin ;; suse) printf '%s\n' libcap-progs ;; alpine) printf '%s\n' libcap-utils ;; *) printf '%s\n' libcap ;; esac ;;
        lsattr)
            case "$FAMILY" in alpine) printf '%s\n' e2fsprogs-extra ;; *) printf '%s\n' e2fsprogs ;; esac ;;
        iptables-save|ip6tables-save) printf '%s\n' iptables ;;
        nft) printf '%s\n' nftables ;;
        awk)
            case "$FAMILY" in alpine) printf '%s\n' gawk ;; debian) printf '%s\n' mawk ;; *) printf '%s\n' gawk ;; esac ;;
        *) printf '%s\n' "$tool" ;;
    esac
}

check_tool() {
    tool=$1
    REASON=not-found
    if [ "$tool" = ca_bundle ]; then
        for bundle in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/ca-bundle.pem /var/lib/ca-certificates/ca-bundle.pem; do
            if [ -s "$bundle" ] && [ -r "$bundle" ]; then REASON=$bundle; return 0; fi
        done
        REASON='no-readable-known-CA-bundle; custom-trust-layout-needs-review'
        return 1
    fi
    location=$(command -v "$tool" 2>/dev/null) || return 1
    REASON=$location
    case "$tool" in
        python3)
            if ! python3 -I -S -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' >/dev/null 2>&1; then
                REASON='Python-3.8+-required'; return 1
            fi ;;
        tar)
            version=$(tar --version 2>/dev/null) || version=
            case "$version" in *'GNU tar'*) ;; *) REASON='GNU-tar-required; BusyBox/bsdtar-not-enough-for-backups'; return 1 ;; esac
            help_text=$(tar --help 2>/dev/null) || help_text=
            for flag in --acls --xattrs --selinux; do
                case "$help_text" in *"$flag"*) ;; *) REASON="tar-missing-$flag"; return 1 ;; esac
            done ;;
        ps)
            version=$(ps --version 2>/dev/null) || version=
            case "$version" in *procps*) ;; *) REASON='procps-ps-required-for-inventory-options'; return 1 ;; esac ;;
    esac
    return 0
}

assess() {
    MISSING=0
    PACKAGES=
    SEEN=
    for tool in $CHECKS; do
        case " $SEEN " in *" $tool "*) continue ;; esac
        SEEN="$SEEN $tool"
        if check_tool "$tool"; then
            printf 'OK      %-16s %s\n' "$tool" "$REASON"
        else
            MISSING=$((MISSING + 1))
            pkg=$(package_for "$tool")
            printf 'MISSING %-16s %-45s package=%s\n' "$tool" "$REASON" "$pkg"
            if [ "$pkg" != MANUAL ]; then
                case " $PACKAGES " in *" $pkg "*) ;; *) PACKAGES="$PACKAGES $pkg" ;; esac
            fi
        fi
    done
}

refresh_metadata() {
    case "$MANAGER" in
        apt-get) apt-get update ;;
        dnf|yum) "$MANAGER" makecache ;;
        zypper) zypper --non-interactive refresh ;;
        apk) apk update ;;
        *) return 1 ;;
    esac
}

install_packages() {
    # Package names come only from the internal static map, never OS data/user text.
    set -- $PACKAGES
    case "$MANAGER" in
        apt-get) DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends -- "$@" ;;
        dnf|yum) "$MANAGER" -y install -- "$@" ;;
        zypper) zypper --non-interactive install --no-recommends -- "$@" ;;
        pacman) pacman -S --needed --noconfirm -- "$@" ;;
        apk) apk add -- "$@" ;;
        *) return 1 ;;
    esac
}

printf '%s\n' '=== CCDC box tool readiness (NOT a security/scoreboard assessment) ==='
printf 'OS: %s | ID=%s | version=%s | family=%s | package manager=%s\n' "$OS_NAME" "$OS_ID" "$OS_VERSION" "$FAMILY" "$MANAGER"
printf 'Profiles (core always included): %s | Install: %s | Metadata refresh: %s | Immutable clue: %s\n' "$PROFILES" "$INSTALL" "$REFRESH" "$IMMUTABLE"
INIT=unknown
if [ -r /proc/1/comm ]; then IFS= read -r INIT < /proc/1/comm || :; fi
printf 'PID 1: %s (do not assume systemd from distro name alone)\n' "$INIT"
printf '%s\n' \
  'RULES: no hunting/removal before noon; preserve whiteteam and supplied whitelists.' \
  'Keep reports/artifacts on assigned infrastructure. No external upload or export.' \
  'AI tools are banned during the event; obtain approval for prewritten scripts.' \
  'Checks only examine tool availability/versions and a CA path, not processes/sockets/implants.' \
  'Package names vary by release/repositories; plans are candidates, not an installation guarantee.' \
  'No upgrade-all, repository additions, remote shell downloads, service/firewall/account edits.' \
  'Package dependencies, maintainer scripts or backend alternatives can STILL change the host.'
assess
printf '\nMissing/insufficient capabilities: %s\nCandidate missing packages:%s\n' "$MISSING" "${PACKAGES:- none/manual}"

STATUS=0
if [ "$MISSING" -gt 0 ]; then STATUS=1; fi
if [ "$INSTALL" = yes ] && [ "$MISSING" -gt 0 ]; then
    if [ "$REFRESH" = yes ] && ! refresh_metadata; then
        printf '%s\n' 'ERROR: metadata refresh failed; no package installation attempted.'
        STATUS=3
    elif install_packages; then
        printf '\n%s\n' '=== Post-install recheck (do not assume package success means tool readiness) ==='
        assess
        STATUS=0
        if [ "$MISSING" -gt 0 ]; then STATUS=1; fi
    else
        printf '%s\n' 'ERROR: package transaction failed; some packages/dependencies may already have changed. Review logs and re-run check-only.'
        STATUS=3
    fi
fi
printf '\nExit status: %s. This checks selected tooling only; verify services, access, free space and event approval separately.\n' "$STATUS"
if [ -n "$REPORT" ]; then printf 'Readiness exit status: %s; report: %s\n' "$STATUS" "$REPORT" >&3; fi
exit "$STATUS"
