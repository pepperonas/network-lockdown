#!/bin/bash
# =============================================================================
# network-lockdown-linux.sh — Emergency Network Lockdown for Linux
# Blocks all traffic except Claude Code CLI (Anthropic API)
# Uses iptables/ip6tables
# =============================================================================

set -eo pipefail 2>/dev/null || set -e

VERSION="1.0.0"

BACKUP_V4="/tmp/iptables-backup-$(date +%s).rules"
BACKUP_V6="/tmp/ip6tables-backup-$(date +%s).rules"
LOCKFILE="/tmp/claude-lockdown.active"
LOG_FILE="/tmp/claude-lockdown.log"

# Farben
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
DIM='\033[2m'

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
    printf '%b\n' "${CYAN}╔══════════════════════════════════════════════════════════╗${NC}"
    printf '%b\n' "${CYAN}║${NC}                                                          ${CYAN}║${NC}"
    printf '%b\n' "${CYAN}║${NC}   ${WHITE}NETWORK LOCKDOWN${NC}                              ${DIM}v${VERSION}${NC}   ${CYAN}║${NC}"
    printf '%b\n' "${CYAN}║${NC}   ${DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}   ${CYAN}║${NC}"
    printf '%b\n' "${CYAN}║${NC}   Kernel-level emergency network isolation               ${CYAN}║${NC}"
    printf '%b\n' "${CYAN}║${NC}   Platform: ${GREEN}Linux${NC} ${DIM}(iptables/Netfilter)${NC}                   ${CYAN}║${NC}"
    printf '%b\n' "${CYAN}║${NC}                                                          ${CYAN}║${NC}"
    printf '%b\n' "${CYAN}║${NC}   ${DIM}Martin Pfeffer - celox.io${NC}                              ${CYAN}║${NC}"
    printf '%b\n' "${CYAN}║${NC}                                                          ${CYAN}║${NC}"
    printf '%b\n' "${CYAN}╚══════════════════════════════════════════════════════════╝${NC}"
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

    log "${YELLOW}╔══════════════════════════════════════════════════╗${NC}"
    log "${YELLOW}║     NETWORK LOCKDOWN — AKTIVIERUNG              ║${NC}"
    log "${YELLOW}╚══════════════════════════════════════════════════╝${NC}"

    # Aktuelle Regeln sichern
    iptables-save  > "$BACKUP_V4" 2>/dev/null || true
    ip6tables-save > "$BACKUP_V6" 2>/dev/null || true
    log "${BLUE}iptables-Backup: $BACKUP_V4${NC}"
    log "${BLUE}ip6tables-Backup: $BACKUP_V6${NC}"

    # IPs auflösen
    log "${BLUE}Löse Anthropic-Domains auf...${NC}"

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

    # Bestehende Regeln flushen
    iptables -F
    iptables -X 2>/dev/null || true
    iptables -F -t nat 2>/dev/null || true
    iptables -F -t mangle 2>/dev/null || true

    # Default Policy: DROP
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT DROP

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

    ip6tables -F
    ip6tables -X 2>/dev/null || true

    # Default Policy: DROP
    ip6tables -P INPUT DROP
    ip6tables -P FORWARD DROP
    ip6tables -P OUTPUT DROP

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
    log "${BLUE}Deaktivieren mit: sudo $0 off${NC}"
    log "${BLUE}Status prüfen:   sudo $0 status${NC}"
    log "${BLUE}IPs aktualisieren: sudo $0 refresh${NC}"
    log ""
    log "${YELLOW}Forensische Analyse-Guideline:${NC}"
    log "${BLUE}  https://github.com/pepperonas/network-lockdown/blob/main/INCIDENT-RESPONSE-GUIDE.md${NC}"
}

deactivate_lockdown() {
    check_root

    log "${YELLOW}╔══════════════════════════════════════════════════╗${NC}"
    log "${YELLOW}║     NETWORK LOCKDOWN — DEAKTIVIERUNG            ║${NC}"
    log "${YELLOW}╚══════════════════════════════════════════════════╝${NC}"

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
        log "${BLUE}IPv4-Regeln aus Backup wiederhergestellt${NC}"
    else
        iptables -F
        iptables -X 2>/dev/null || true
        iptables -P INPUT ACCEPT
        iptables -P FORWARD ACCEPT
        iptables -P OUTPUT ACCEPT
        log "${BLUE}IPv4-Regeln auf ACCEPT zurückgesetzt${NC}"
    fi

    if [[ -n "$backup_v6" && -f "$backup_v6" ]]; then
        ip6tables-restore < "$backup_v6"
        log "${BLUE}IPv6-Regeln aus Backup wiederhergestellt${NC}"
    else
        ip6tables -F
        ip6tables -X 2>/dev/null || true
        ip6tables -P INPUT ACCEPT
        ip6tables -P FORWARD ACCEPT
        ip6tables -P OUTPUT ACCEPT
        log "${BLUE}IPv6-Regeln auf ACCEPT zurückgesetzt${NC}"
    fi

    rm -f "$LOCKFILE"

    log ""
    log "${GREEN}Lockdown DEAKTIVIERT. Netzwerk ist wiederhergestellt.${NC}"
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
    printf '%b\n' "${BLUE}IPv4-Regeln (iptables):${NC}"
    iptables -L -n --line-numbers 2>/dev/null || echo "(iptables nicht verfügbar)"

    echo ""
    printf '%b\n' "${BLUE}IPv6-Regeln (ip6tables):${NC}"
    ip6tables -L -n --line-numbers 2>/dev/null || echo "(ip6tables nicht verfügbar)"

    echo ""
    printf '%b\n' "${BLUE}Claude Code Konnektivitätstest:${NC}"
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

    log "${BLUE}Aktualisiere Anthropic-IPs — Lockdown wird neu aufgebaut...${NC}"

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
    printf '%b\n' "${BLUE}Aktuelle IPv4-Regeln:${NC}"
    iptables -L -n -v 2>/dev/null || echo "(nicht verfügbar)"
    echo ""
    printf '%b\n' "${BLUE}Aktuelle IPv6-Regeln:${NC}"
    ip6tables -L -n -v 2>/dev/null || echo "(nicht verfügbar)"
}

show_help() {
    echo ""
    printf '%b\n' "${BLUE}network-lockdown-linux.sh — Emergency Network Lockdown für Linux${NC}"
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
    echo "  help     Diese Hilfe anzeigen"
    echo ""
    printf '%b\n' "${YELLOW}Hinweis: Erfordert root-Rechte (sudo).${NC}"
    printf '%b\n' "${YELLOW}Benötigt: iptables, dig (dnsutils), curl${NC}"
    echo ""
    printf '%b\n' "${YELLOW}Forensische Analyse-Guideline:${NC}"
    printf '%b\n' "${BLUE}  https://github.com/pepperonas/network-lockdown/blob/main/INCIDENT-RESPONSE-GUIDE.md${NC}"
    echo ""
}

# === Main ===
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
    help|--help|-h)
        show_help
        ;;
    *)
        printf '%b\n' "${RED}Unbekannter Befehl: $1${NC}"
        show_help
        exit 1
        ;;
esac
