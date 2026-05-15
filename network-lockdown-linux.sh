#!/bin/bash
# =============================================================================
# network-lockdown-linux.sh — Emergency Network Lockdown for Linux
# Blocks all traffic except Claude Code CLI (Anthropic API)
# Uses iptables/ip6tables
# =============================================================================

set -eo pipefail 2>/dev/null || set -e

VERSION="1.2.0"
GITHUB_RAW="https://github.com/pepperonas/network-lockdown/raw/main"

BACKUP_V4="/tmp/iptables-backup-$(date +%s).rules"
BACKUP_V6="/tmp/ip6tables-backup-$(date +%s).rules"
LOCKFILE="/tmp/claude-lockdown.active"
LOG_FILE="/tmp/claude-lockdown.log"
STRICT_MODE=0

# Farben
RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;96m'
MAGENTA='\033[0;95m'
WHITE='\033[1;37m'
DIM='\033[0;90m'
NC='\033[0m'

log() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] $1"
    echo "$msg" >> "$LOG_FILE"
    printf '%b\n' "$1"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        printf '%b\n' "${RED}Dieses Script benötigt root-Rechte.${NC}"
        echo "Starte mit: sudo $0 $*"
        exit 1
    fi
}

check_dependencies() {
    local missing=()
    for cmd in iptables ip6tables dig curl; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        log "${RED}Fehlende Programme: ${missing[*]}${NC}"
        log "Installiere z.B. mit: apt install iptables dnsutils curl"
        exit 1
    fi
}

show_banner() {
    printf '\n'
    printf '%b\n' "${MAGENTA}╔══════════════════════════════════════════════════════════╗${NC}"
    printf '%b\n' "${MAGENTA}║${NC}                                                          ${MAGENTA}║${NC}"
    printf '%b\n' "${MAGENTA}║${NC}   ${WHITE}NETWORK LOCKDOWN${NC}                              ${DIM}v${VERSION}${NC}   ${MAGENTA}║${NC}"
    printf '%b\n' "${MAGENTA}║${NC}   ${DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}   ${MAGENTA}║${NC}"
    printf '%b\n' "${MAGENTA}║${NC}   Kernel-level emergency network isolation               ${MAGENTA}║${NC}"
    printf '%b\n' "${MAGENTA}║${NC}   Platform: ${GREEN}Linux${NC} ${DIM}(iptables/Netfilter)${NC}                   ${MAGENTA}║${NC}"
    printf '%b\n' "${MAGENTA}║${NC}                                                          ${MAGENTA}║${NC}"
    printf '%b\n' "${MAGENTA}║${NC}   ${DIM}Martin Pfeffer - celox.io${NC}                              ${MAGENTA}║${NC}"
    printf '%b\n' "${MAGENTA}║${NC}                                                          ${MAGENTA}║${NC}"
    printf '%b\n' "${MAGENTA}╚══════════════════════════════════════════════════════════╝${NC}"
    printf '\n'
}

# Anthropic-Domains auflösen und IPs sammeln
resolve_ips() {
    local domains=(
        "api.anthropic.com"
        "statsig.anthropic.com"
        "api.statsig.com"
    )
    local ips=()
    local resolved

    for domain in "${domains[@]}"; do
        # IPv4
        resolved=$(dig +short A "$domain" 2>/dev/null | grep -E '^[0-9]+\.' || true)
        for ip in $resolved; do
            [[ -n "$ip" ]] && ips+=("$ip")
        done

        # IPv6
        resolved=$(dig +short AAAA "$domain" 2>/dev/null | grep -E '^[0-9a-f]+:' || true)
        for ip in $resolved; do
            [[ -n "$ip" ]] && ips+=("$ip")
        done
    done

    printf '%s\n' "${ips[@]}" | sort -u
}

# Erkennung beliebiger Container-/VM-Runtimes (Docker, Podman, LXC/LXD,
# containerd, Kubernetes/CNI). Liefert 0 wenn etwas Verdaechtiges laeuft.
detect_containers() {
    # Daemons
    for svc in docker docker.socket containerd podman lxc lxd k3s; do
        if systemctl is-active "$svc" &>/dev/null; then return 0; fi
    done
    # Tools + Bridges
    if command -v docker &>/dev/null && docker info &>/dev/null; then return 0; fi
    if command -v podman &>/dev/null && podman info &>/dev/null 2>&1; then return 0; fi
    # iptables-Chains die Container-Runtimes anlegen
    for chain in DOCKER-USER CNI-FORWARD KUBE-FORWARD LIBVIRT_FWO; do
        if iptables -L "$chain" -n &>/dev/null; then return 0; fi
    done
    # Bekannte Bridge-Namen
    if ip -o link show 2>/dev/null | grep -qE ': (docker0|br-[0-9a-f]+|podman[0-9]*|cni-podman[0-9]+|lxcbr[0-9]+|lxdbr[0-9]+|cni0|cilium_host|flannel\.|kube-bridge|virbr[0-9]+)'; then
        return 0
    fi
    return 1
}

# Backwards-compatible alias
detect_docker() { detect_containers; }

# Default-Route-Interface ermitteln (das wollen wir NICHT blockieren).
get_uplink_iface() {
    ip route show default 2>/dev/null | awk '/^default/ {print $5; exit}'
}

# Alle suspekten Bridges/veth-Geraete auflisten (alles ausser Loopback + Uplink).
# Heuristik: erfasst auch unbekannte CNI-Plugins, podman-Netze, libvirt etc.
list_container_bridges() {
    local uplink
    uplink=$(get_uplink_iface)

    ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | awk '{print $1}' | \
    while read -r iface; do
        [[ -z "$iface" ]] && continue
        [[ "$iface" == "lo" ]] && continue
        [[ "$iface" == "$uplink" ]] && continue
        # Nur Bridges, veth-Endpunkte, TUN/TAP, WireGuard, dummy
        local type
        type=$(ip -d -o link show "$iface" 2>/dev/null | grep -oE 'link/[a-z]+|veth|bridge|tun|wireguard|vxlan|geneve|ipip' | head -1)
        case "$iface" in
            docker*|br-*|podman*|cni-*|cni*|lxcbr*|lxdbr*|virbr*|flannel*|cilium*|kube-*|vnet*|tap*)
                echo "$iface"
                ;;
            *)
                # Generische Erkennung ueber type
                if echo "$type" | grep -qE 'veth|bridge|tun|vxlan|geneve'; then
                    echo "$iface"
                fi
                ;;
        esac
    done
}

# Container-/Bridge-Verkehr explizit blockieren.
# Hintergrund: Ein laufender Container-Daemon kann iptables-Regeln neu
# erstellen und damit die FORWARD-Policy umgehen. Diese Regeln werden VOR
# Daemon-Regeln in DOCKER-USER/CNI-FORWARD/FORWARD platziert (Position 1).
block_container_traffic() {
    if ! detect_containers; then
        return
    fi

    log "${YELLOW}Container/VM-Runtime erkannt — fuege explizite Block-Regeln ein${NC}"
    log "${YELLOW}  Empfehlung: laufende Daemons stoppen (docker, podman, containerd, libvirtd, ...)${NC}"

    # User-/CNI-Chains: werden VOR Daemon-eigenen Regeln evaluiert
    for chain in DOCKER-USER CNI-FORWARD KUBE-FORWARD LIBVIRT_FWO; do
        if iptables -L "$chain" -n &>/dev/null; then
            iptables -I "$chain" 1 -j DROP 2>/dev/null || true
            log "${CYAN}  iptables $chain: DROP eingefuegt${NC}"
        fi
        if ip6tables -L "$chain" -n &>/dev/null; then
            ip6tables -I "$chain" 1 -j DROP 2>/dev/null || true
        fi
    done

    # Alle verdaechtigen Bridge-/veth-Interfaces in FORWARD blockieren.
    # Sicherheitsnetz fuer den Fall, dass ein Daemon nach unserem Flush
    # neue FORWARD-Regeln per -I einfuegt.
    local bridges
    bridges=$(list_container_bridges | sort -u)
    if [[ -z "$bridges" ]]; then
        log "${DIM}  Keine Container-Bridges gefunden${NC}"
        return
    fi
    for br in $bridges; do
        iptables  -I FORWARD 1 -i "$br" -j DROP 2>/dev/null || true
        iptables  -I FORWARD 1 -o "$br" -j DROP 2>/dev/null || true
        ip6tables -I FORWARD 1 -i "$br" -j DROP 2>/dev/null || true
        ip6tables -I FORWARD 1 -o "$br" -j DROP 2>/dev/null || true
        log "${CYAN}  FORWARD-DROP fuer Bridge: $br${NC}"
    done
}

# Backwards-compatible alias
block_docker_traffic() { block_container_traffic; }

# nftables-Detection: auf modernen Distros (Debian 11+, RHEL 9+, Fedora) ist
# nftables das Default-Backend. `iptables` ist meist `iptables-nft` (Shim).
# Tools wie firewalld koennen direkt nft-Regeln schreiben, die unser
# iptables-save-Backup nicht erfasst.
check_nftables() {
    if ! command -v nft &>/dev/null; then return; fi

    # Existieren native nft-tabellen ausser unseren iptables-nft Tabellen?
    local nft_tables
    nft_tables=$(nft list tables 2>/dev/null | grep -vE '^table (ip|ip6) (filter|nat|mangle|raw|security)$' | head -20)
    if [[ -n "$nft_tables" ]]; then
        log "${YELLOW}nftables-Tabellen erkannt, die nicht ueber iptables verwaltet werden:${NC}"
        echo "$nft_tables" | while read -r line; do
            log "${DIM}  $line${NC}"
        done
        log "${YELLOW}  Diese Regeln werden NICHT vom Backup erfasst und nicht beim 'off' wiederhergestellt.${NC}"
        log "${YELLOW}  Tools wie firewalld, eBPF/Cilium koennen sie geschrieben haben.${NC}"
    fi

    # Check ob firewalld laeuft (haeufigste Quelle)
    if systemctl is-active firewalld &>/dev/null; then
        log "${YELLOW}firewalld laeuft — wird parallel zu unseren iptables-Regeln evaluiert.${NC}"
        log "${DIM}  Stoppen: systemctl stop firewalld${NC}"
    fi
}

# System-DNS-Server ermitteln
get_dns_servers() {
    # systemd-resolved
    if command -v resolvectl &>/dev/null; then
        resolvectl status 2>/dev/null | grep 'DNS Servers' | awk '{for(i=3;i<=NF;i++) print $i}' | sort -u
        return
    fi
    # Fallback: /etc/resolv.conf
    grep -E '^\s*nameserver' /etc/resolv.conf 2>/dev/null | awk '{print $2}' | sort -u
}

activate_lockdown() {
    check_root
    check_dependencies

    if [[ -f "$LOCKFILE" ]]; then
        log "${YELLOW}Lockdown ist bereits aktiv. Zum Neustart erst deaktivieren: $0 off${NC}"
        exit 1
    fi

    log "${MAGENTA}╔══════════════════════════════════════════════════╗${NC}"
    log "${MAGENTA}║     NETWORK LOCKDOWN — AKTIVIERUNG              ║${NC}"
    log "${MAGENTA}╚══════════════════════════════════════════════════╝${NC}"

    # Aktuelle Regeln sichern
    iptables-save  > "$BACKUP_V4" 2>/dev/null || true
    ip6tables-save > "$BACKUP_V6" 2>/dev/null || true
    log "${CYAN}iptables-Backup: $BACKUP_V4${NC}"
    log "${CYAN}ip6tables-Backup: $BACKUP_V6${NC}"

    # IPs auflösen
    log "${CYAN}Löse Anthropic-Domains auf...${NC}"

    local ipv4_ips=()
    local ipv6_ips=()
    local resolved_ips
    resolved_ips=$(resolve_ips)

    for ip in $resolved_ips; do
        if [[ "$ip" == *:* ]]; then
            ipv6_ips+=("$ip")
        else
            ipv4_ips+=("$ip")
        fi
    done

    if [[ ${#ipv4_ips[@]} -eq 0 && ${#ipv6_ips[@]} -eq 0 ]]; then
        log "${RED}Keine IPs aufgelöst — Abbruch. Prüfe deine DNS-Konfiguration.${NC}"
        exit 1
    fi

    log "${GREEN}Aufgelöste IPv4: ${ipv4_ips[*]}${NC}"
    [[ ${#ipv6_ips[@]} -gt 0 ]] && log "${GREEN}Aufgelöste IPv6: ${ipv6_ips[*]}${NC}"

    local dns_servers
    dns_servers=$(get_dns_servers)

    # ──────────────────────────────────────────────
    # IPv4-Regeln
    # ──────────────────────────────────────────────

    # WICHTIG: Default Policy DROP VOR Flush setzen, damit waehrend des
    # Regel-Wiederaufbaus keine Pakete durchschluepfen koennen.
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT DROP

    # Bestehende Regeln flushen
    iptables -F
    iptables -X 2>/dev/null || true
    iptables -F -t nat 2>/dev/null || true
    iptables -F -t mangle 2>/dev/null || true

    # Loopback erlauben
    iptables -A INPUT  -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT

    # Etablierte/Verwandte Verbindungen erlauben (Antwortpakete)
    iptables -A INPUT  -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # DNS erlauben
    if [[ -n "$dns_servers" ]]; then
        for dns in $dns_servers; do
            # Nur IPv4-DNS hier
            if [[ "$dns" != *:* ]]; then
                iptables -A OUTPUT -p udp -d "$dns" --dport 53 -j ACCEPT
                iptables -A OUTPUT -p tcp -d "$dns" --dport 53 -j ACCEPT
            fi
        done
    else
        # Fallback: DNS generell erlauben
        iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
        iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT
    fi

    # Anthropic IPv4 erlauben
    for ip in "${ipv4_ips[@]}"; do
        iptables -A OUTPUT -p tcp -d "$ip" --dport 443 -j ACCEPT
    done

    # ──────────────────────────────────────────────
    # IPv6-Regeln
    # ──────────────────────────────────────────────

    # Default Policy DROP zuerst (vor Flush)
    ip6tables -P INPUT DROP
    ip6tables -P FORWARD DROP
    ip6tables -P OUTPUT DROP

    ip6tables -F
    ip6tables -X 2>/dev/null || true

    # Loopback erlauben
    ip6tables -A INPUT  -i lo -j ACCEPT
    ip6tables -A OUTPUT -o lo -j ACCEPT

    # Etablierte Verbindungen
    ip6tables -A INPUT  -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    ip6tables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # ICMPv6 (nötig für IPv6-Grundfunktionen wie NDP)
    ip6tables -A INPUT  -p icmpv6 -j ACCEPT
    ip6tables -A OUTPUT -p icmpv6 -j ACCEPT

    # DNS (IPv6-Resolver)
    if [[ -n "$dns_servers" ]]; then
        for dns in $dns_servers; do
            if [[ "$dns" == *:* ]]; then
                ip6tables -A OUTPUT -p udp -d "$dns" --dport 53 -j ACCEPT
                ip6tables -A OUTPUT -p tcp -d "$dns" --dport 53 -j ACCEPT
            fi
        done
    else
        ip6tables -A OUTPUT -p udp --dport 53 -j ACCEPT
        ip6tables -A OUTPUT -p tcp --dport 53 -j ACCEPT
    fi

    # Anthropic IPv6 erlauben
    for ip in "${ipv6_ips[@]}"; do
        ip6tables -A OUTPUT -p tcp -d "$ip" --dport 443 -j ACCEPT
    done

    # ──────────────────────────────────────────────
    # Container-/VM-Verkehr blockieren + nftables-Awareness
    # ──────────────────────────────────────────────
    block_container_traffic
    check_nftables

    # ──────────────────────────────────────────────
    # Strict-Modus: bestehende Verbindungen killen
    # ──────────────────────────────────────────────
    if [[ "$STRICT_MODE" == "1" ]]; then
        log "${MAGENTA}Strict-Modus: leere conntrack-Tabelle...${NC}"
        if command -v conntrack &>/dev/null; then
            conntrack -F 2>/dev/null && \
                log "${GREEN}  conntrack-Eintraege geloescht — bestehende Sessions verlieren ESTABLISHED${NC}"
        else
            # Fallback ueber sysfs (loescht alle conntrack states)
            if [[ -w /proc/sys/net/netfilter/nf_conntrack_max ]]; then
                local cmax
                cmax=$(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null)
                echo 0 > /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null
                echo "$cmax" > /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null
                log "${GREEN}  conntrack-Tabelle ueber sysfs zurueckgesetzt${NC}"
            else
                log "${YELLOW}  conntrack-Tool nicht installiert. Installiere: apt install conntrack${NC}"
            fi
        fi
        # Aktive TCP-Sockets zwangsweise schliessen (best effort)
        if command -v ss &>/dev/null; then
            ss --kill state established 2>/dev/null || true
            log "${GREEN}  Bestehende TCP-Sockets gekillt${NC}"
        fi
    fi

    # Lockfile erstellen
    echo "$(date)" > "$LOCKFILE"
    echo "$BACKUP_V4" >> "$LOCKFILE"
    echo "$BACKUP_V6" >> "$LOCKFILE"

    log ""
    log "${GREEN}Lockdown AKTIV.${NC}"
    log "${GREEN}  Erlaubt:  Anthropic API (Claude Code CLI)${NC}"
    log "${GREEN}  Erlaubt:  DNS-Auflösung${NC}"
    log "${GREEN}  Erlaubt:  Localhost/Loopback${NC}"
    log "${RED}  Blockiert: Gesamter übriger Netzwerkverkehr${NC}"
    log ""
    log "${CYAN}Deaktivieren mit: sudo $0 off${NC}"
    log "${CYAN}Status prüfen:   sudo $0 status${NC}"
    log "${CYAN}IPs aktualisieren: sudo $0 refresh${NC}"
    log ""
    log "${MAGENTA}Forensische Analyse-Guideline:${NC}"
    log "${CYAN}  https://github.com/pepperonas/network-lockdown/blob/main/INCIDENT-RESPONSE-GUIDE.md${NC}"
}

deactivate_lockdown() {
    check_root

    log "${MAGENTA}╔══════════════════════════════════════════════════╗${NC}"
    log "${MAGENTA}║     NETWORK LOCKDOWN — DEAKTIVIERUNG            ║${NC}"
    log "${MAGENTA}╚══════════════════════════════════════════════════╝${NC}"

    local backup_v4=""
    local backup_v6=""

    # Backup-Pfade aus Lockfile lesen
    if [[ -f "$LOCKFILE" ]]; then
        backup_v4=$(sed -n '2p' "$LOCKFILE")
        backup_v6=$(sed -n '3p' "$LOCKFILE")
    fi

    # Aus Backup wiederherstellen oder auf ACCEPT zurücksetzen
    if [[ -n "$backup_v4" && -f "$backup_v4" ]]; then
        iptables-restore < "$backup_v4"
        log "${CYAN}IPv4-Regeln aus Backup wiederhergestellt${NC}"
    else
        iptables -F
        iptables -X 2>/dev/null || true
        iptables -P INPUT ACCEPT
        iptables -P FORWARD ACCEPT
        iptables -P OUTPUT ACCEPT
        log "${CYAN}IPv4-Regeln auf ACCEPT zurückgesetzt${NC}"
    fi

    if [[ -n "$backup_v6" && -f "$backup_v6" ]]; then
        ip6tables-restore < "$backup_v6"
        log "${CYAN}IPv6-Regeln aus Backup wiederhergestellt${NC}"
    else
        ip6tables -F
        ip6tables -X 2>/dev/null || true
        ip6tables -P INPUT ACCEPT
        ip6tables -P FORWARD ACCEPT
        ip6tables -P OUTPUT ACCEPT
        log "${CYAN}IPv6-Regeln auf ACCEPT zurückgesetzt${NC}"
    fi

    rm -f "$LOCKFILE"

    log ""
    log "${GREEN}Lockdown DEAKTIVIERT. Netzwerk ist wiederhergestellt.${NC}"

    if detect_containers; then
        log ""
        log "${YELLOW}Hinweis:${NC} Container-Netzwerke wurden beim Lockdown geflusht."
        log "${YELLOW}        Falls Container kein Netz haben:${NC}"
        log "${CYAN}        systemctl restart docker  # bzw. podman / containerd / libvirtd${NC}"
    fi
}

show_status() {
    echo ""
    if [[ -f "$LOCKFILE" ]]; then
        local activated_at
        activated_at=$(head -1 "$LOCKFILE")
        printf '%b\n' "${RED}Status: LOCKDOWN AKTIV${NC}"
        printf '%b\n' "Aktiviert: $activated_at"
    else
        printf '%b\n' "${GREEN}Status: Normal (kein Lockdown)${NC}"
    fi

    echo ""
    printf '%b\n' "${CYAN}IPv4-Regeln (iptables):${NC}"
    iptables -L -n --line-numbers 2>/dev/null || echo "(iptables nicht verfügbar)"

    echo ""
    printf '%b\n' "${CYAN}IPv6-Regeln (ip6tables):${NC}"
    ip6tables -L -n --line-numbers 2>/dev/null || echo "(ip6tables nicht verfügbar)"

    echo ""
    if detect_containers; then
        printf '%b\n' "${YELLOW}Container/VM-Runtime erkannt:${NC} Pakete koennen iptables-Regeln umgehen, wenn der Daemon laeuft."
        printf '%b\n' "${DIM}  Stoppen: systemctl stop docker docker.socket containerd podman libvirtd${NC}"
        local bridges
        bridges=$(list_container_bridges | tr '\n' ' ')
        [[ -n "$bridges" ]] && printf '%b\n' "${DIM}  Erkannte Bridges: $bridges${NC}"
        echo ""
    fi
    if systemctl is-active firewalld &>/dev/null; then
        printf '%b\n' "${YELLOW}firewalld laeuft:${NC} schreibt parallel in nftables und kann unsere Regeln umgehen."
        printf '%b\n' "${DIM}  Stoppen: systemctl stop firewalld${NC}"
        echo ""
    fi

    printf '%b\n' "${CYAN}Claude Code Konnektivitätstest:${NC}"
    if curl -sS --connect-timeout 5 -o /dev/null -w "%{http_code}" https://api.anthropic.com 2>/dev/null | grep -qE "^[245]"; then
        printf '%b\n' "${GREEN}  api.anthropic.com: erreichbar${NC}"
    else
        printf '%b\n' "${RED}  api.anthropic.com: NICHT erreichbar${NC}"
    fi

    if [[ -f "$LOCKFILE" ]]; then
        if curl -sS --connect-timeout 3 -o /dev/null https://www.google.com 2>/dev/null; then
            printf '%b\n' "${YELLOW}  google.com: erreichbar (Lockdown möglicherweise undicht!)${NC}"
        else
            printf '%b\n' "${GREEN}  google.com: blockiert (Lockdown funktioniert)${NC}"
        fi
    fi
}

refresh_ips() {
    check_root

    if [[ ! -f "$LOCKFILE" ]]; then
        log "${YELLOW}Kein aktiver Lockdown. Nichts zu aktualisieren.${NC}"
        exit 1
    fi

    # Strict-Modus beim Refresh deaktivieren: wuerde die laufende
    # Anthropic-Verbindung killen, was Selbstzweck verfehlt.
    STRICT_MODE=0

    log "${CYAN}Aktualisiere Anthropic-IPs — Lockdown wird neu aufgebaut...${NC}"

    # Backup-Pfade übernehmen, bevor Lockfile gelöscht wird
    local backup_v4
    local backup_v6
    backup_v4=$(sed -n '2p' "$LOCKFILE")
    backup_v6=$(sed -n '3p' "$LOCKFILE")

    rm -f "$LOCKFILE"
    activate_lockdown

    # Originale Backup-Pfade wiederherstellen
    if [[ -f "$LOCKFILE" ]]; then
        local new_date
        new_date=$(head -1 "$LOCKFILE")
        echo "$new_date" > "$LOCKFILE"
        echo "$backup_v4" >> "$LOCKFILE"
        echo "$backup_v6" >> "$LOCKFILE"
    fi

    log "${GREEN}IPs aktualisiert und Regeln neu geladen.${NC}"
}

show_rules() {
    echo ""
    printf '%b\n' "${CYAN}Aktuelle IPv4-Regeln:${NC}"
    iptables -L -n -v 2>/dev/null || echo "(nicht verfügbar)"
    echo ""
    printf '%b\n' "${CYAN}Aktuelle IPv6-Regeln:${NC}"
    ip6tables -L -n -v 2>/dev/null || echo "(nicht verfügbar)"
}

download_guide() {
    local dest="${2:-.}"
    log "${CYAN}Lade Incident-Response-Guide herunter...${NC}"

    if ! command -v curl &>/dev/null; then
        log "${RED}curl wird benötigt, ist aber nicht installiert.${NC}"
        exit 1
    fi

    curl -fSL -o "$dest/INCIDENT-RESPONSE-GUIDE.pdf" \
        "$GITHUB_RAW/INCIDENT-RESPONSE-GUIDE.pdf" 2>/dev/null
    curl -fSL -o "$dest/INCIDENT-RESPONSE-GUIDE.en.pdf" \
        "$GITHUB_RAW/INCIDENT-RESPONSE-GUIDE.en.pdf" 2>/dev/null

    if [[ -f "$dest/INCIDENT-RESPONSE-GUIDE.pdf" && -f "$dest/INCIDENT-RESPONSE-GUIDE.en.pdf" ]]; then
        log "${GREEN}Heruntergeladen:${NC}"
        log "  $dest/INCIDENT-RESPONSE-GUIDE.pdf (Deutsch)"
        log "  $dest/INCIDENT-RESPONSE-GUIDE.en.pdf (English)"
    else
        log "${RED}Download fehlgeschlagen. Prüfe deine Internetverbindung.${NC}"
        exit 1
    fi
}

show_help() {
    echo ""
    printf '%b\n' "${CYAN}network-lockdown-linux.sh — Emergency Network Lockdown für Linux${NC}"
    echo ""
    echo "Blockiert den gesamten Netzwerkverkehr außer Claude Code CLI."
    echo "Nutzt iptables/ip6tables."
    echo ""
    printf '%b\n' "Verwendung: ${GREEN}sudo $0 <befehl>${NC}"
    echo ""
    echo "  on       Lockdown aktivieren"
    echo "  off      Lockdown deaktivieren, Netzwerk wiederherstellen"
    echo "  status   Aktuellen Status und Regeln anzeigen"
    echo "  refresh  Anthropic-IPs neu auflösen (bei CDN-Wechsel)"
    echo "  rules    Aktuelle iptables-Regeln anzeigen"
    echo "  guide    Incident-Response-Guide (PDF) herunterladen"
    echo "  help     Diese Hilfe anzeigen"
    echo ""
    echo "Optionen:"
    echo "  --strict, -s  Bestehende Verbindungen zwangsweise schliessen"
    echo "                (conntrack -F + ss --kill). Verhindert Weiterlaufen"
    echo "                bereits offener Malware-Sessions."
    echo ""
    printf '%b\n' "${YELLOW}Hinweis: Erfordert root-Rechte (sudo).${NC}"
    printf '%b\n' "${YELLOW}Benötigt: iptables, dig (dnsutils), curl${NC}"
    echo ""
    printf '%b\n' "${MAGENTA}Forensische Analyse-Guideline:${NC}"
    printf '%b\n' "${CYAN}  https://github.com/pepperonas/network-lockdown/blob/main/INCIDENT-RESPONSE-GUIDE.md${NC}"
    echo ""
}

# === Main ===
# Optionales --strict/--soft Flag (an beliebiger Position)
for arg in "$@"; do
    case "$arg" in
        --strict|-s) STRICT_MODE=1 ;;
    esac
done

show_banner
case "${1:-help}" in
    on|activate|enable)
        activate_lockdown
        ;;
    off|deactivate|disable)
        deactivate_lockdown
        ;;
    status)
        show_status
        ;;
    refresh)
        refresh_ips
        ;;
    rules|show)
        show_rules
        ;;
    guide)
        download_guide "$@"
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        printf '%b\n' "${RED}Unbekannter Befehl: $1${NC}"
        show_help
        exit 1
        ;;
esac
