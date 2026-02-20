#!/bin/bash
# =============================================================================
# network-lockdown.sh — Emergency Network Lockdown for macOS
# Blocks all traffic except Claude Code CLI (Anthropic API)
# Uses macOS built-in pfctl (Packet Filter)
# =============================================================================

set -eo pipefail 2>/dev/null || set -e

PF_CONF="/etc/pf.anchors/claude-lockdown"
PF_ANCHOR_NAME="claude-lockdown"
BACKUP_CONF="/tmp/pf-backup-$(date +%s).conf"
LOCKFILE="/tmp/claude-lockdown.active"
LOG_FILE="/tmp/claude-lockdown.log"

# Farben
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] $1"
    echo "$msg" >> "$LOG_FILE"
    echo -e "$1"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}Dieses Script benötigt root-Rechte.${NC}"
        echo "Starte mit: sudo $0 $*"
        exit 1
    fi
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

    # Deduplizieren
    printf '%s\n' "${ips[@]}" | sort -u
}

# Bekannte DNS-Resolver (für die Domain-Auflösung)
get_dns_servers() {
    # Aktuelle System-DNS-Server auslesen
    scutil --dns 2>/dev/null | grep 'nameserver\[' | awk '{print $3}' | sort -u
}

generate_pf_rules() {
    local ipv4_ips=()
    local ipv6_ips=()
    local dns_servers

    log "${BLUE}Löse Anthropic-Domains auf...${NC}"

    local resolved_ips
    resolved_ips=$(resolve_ips)
    for ip in $resolved_ips; do
        if [[ "$ip" == *:* ]]; then
            ipv6_ips+=("$ip")
        else
            ipv4_ips+=("$ip")
        fi
    done

    dns_servers=$(get_dns_servers)

    if [[ ${#ipv4_ips[@]} -eq 0 && ${#ipv6_ips[@]} -eq 0 ]]; then
        log "${RED}Keine IPs aufgelöst — Abbruch. Prüfe deine DNS-Konfiguration.${NC}"
        exit 1
    fi

    log "${GREEN}Aufgelöste IPv4: ${ipv4_ips[*]}${NC}"
    [[ ${#ipv6_ips[@]} -gt 0 ]] && log "${GREEN}Aufgelöste IPv6: ${ipv6_ips[*]}${NC}"

    # PF-Regeln erstellen
    cat > "$PF_CONF" << 'HEADER'
# ============================================================
# Claude Code Lockdown — automatisch generiert
# Blockiert allen Traffic außer Anthropic API + DNS
# ============================================================

# Loopback immer erlauben
pass quick on lo0 all

HEADER

    # DNS erlauben (nötig für Domain-Auflösung bei IP-Wechsel)
    if [[ -n "$dns_servers" ]]; then
        echo "# DNS-Verkehr zu System-Resolvern erlauben" >> "$PF_CONF"
        while IFS= read -r dns; do
            [[ -n "$dns" ]] && echo "pass out quick proto { tcp, udp } to $dns port 53" >> "$PF_CONF"
        done <<< "$dns_servers"
        echo "" >> "$PF_CONF"
    else
        # Fallback: DNS generell erlauben
        echo "# DNS generell erlauben (keine spezifischen Resolver gefunden)" >> "$PF_CONF"
        echo "pass out quick proto { tcp, udp } to any port 53" >> "$PF_CONF"
        echo "" >> "$PF_CONF"
    fi

    # Anthropic IPv4 erlauben
    echo "# Anthropic API — IPv4" >> "$PF_CONF"
    for ip in "${ipv4_ips[@]}"; do
        echo "pass out quick proto tcp to $ip port 443" >> "$PF_CONF"
    done
    echo "" >> "$PF_CONF"

    # Anthropic IPv6 erlauben
    if [[ ${#ipv6_ips[@]} -gt 0 ]]; then
        echo "# Anthropic API — IPv6" >> "$PF_CONF"
        for ip in "${ipv6_ips[@]}"; do
            echo "pass out quick proto tcp to $ip port 443" >> "$PF_CONF"
        done
        echo "" >> "$PF_CONF"
    fi

    # Etablierte Verbindungen (Antworten) erlauben
    echo "# Antwortpakete für erlaubte Verbindungen" >> "$PF_CONF"
    echo "pass in quick proto tcp from any to any flags A/A" >> "$PF_CONF"
    echo "" >> "$PF_CONF"

    # Alles andere blockieren
    cat >> "$PF_CONF" << 'FOOTER'
# ============================================================
# ALLES ANDERE BLOCKIEREN
# ============================================================
block drop out quick on ! lo0 all
block drop in quick on ! lo0 all
FOOTER

    log "${GREEN}PF-Regeln geschrieben: $PF_CONF${NC}"
}

activate_lockdown() {
    check_root

    if [[ -f "$LOCKFILE" ]]; then
        log "${YELLOW}Lockdown ist bereits aktiv. Zum Neustart erst deaktivieren: $0 off${NC}"
        exit 1
    fi

    log "${YELLOW}╔══════════════════════════════════════════════════╗${NC}"
    log "${YELLOW}║     NETWORK LOCKDOWN — AKTIVIERUNG              ║${NC}"
    log "${YELLOW}╚══════════════════════════════════════════════════╝${NC}"

    # Aktuelle pf-Konfiguration sichern
    if pfctl -sr > "$BACKUP_CONF" 2>/dev/null; then
        log "${BLUE}Aktuelle pf-Regeln gesichert: $BACKUP_CONF${NC}"
    fi

    generate_pf_rules

    # Regeln in pf laden
    # Bestehende Regeln flushen und neue laden
    pfctl -F all 2>/dev/null || true

    # Anchor in pf.conf registrieren (falls nicht vorhanden)
    if ! grep -q "$PF_ANCHOR_NAME" /etc/pf.conf 2>/dev/null; then
        cp /etc/pf.conf /etc/pf.conf.bak
        echo "anchor \"$PF_ANCHOR_NAME\"" >> /etc/pf.conf
        echo "load anchor \"$PF_ANCHOR_NAME\" from \"$PF_CONF\"" >> /etc/pf.conf
    fi

    # Regeln direkt laden und pf aktivieren
    pfctl -f "$PF_CONF" 2>/dev/null
    pfctl -e 2>/dev/null || true

    # Lockfile erstellen
    echo "$(date)" > "$LOCKFILE"
    echo "$BACKUP_CONF" >> "$LOCKFILE"

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
}

deactivate_lockdown() {
    check_root

    log "${YELLOW}╔══════════════════════════════════════════════════╗${NC}"
    log "${YELLOW}║     NETWORK LOCKDOWN — DEAKTIVIERUNG            ║${NC}"
    log "${YELLOW}╚══════════════════════════════════════════════════╝${NC}"

    # pf deaktivieren und Regeln flushen
    pfctl -F all 2>/dev/null || true
    pfctl -d 2>/dev/null || true

    # Anchor aus pf.conf entfernen
    if [[ -f /etc/pf.conf.bak ]]; then
        cp /etc/pf.conf.bak /etc/pf.conf
        log "${BLUE}pf.conf aus Backup wiederhergestellt${NC}"
    else
        # Manuell entfernen
        sed -i '' "/$PF_ANCHOR_NAME/d" /etc/pf.conf 2>/dev/null || true
    fi

    # Standard macOS pf-Regeln wiederherstellen
    pfctl -f /etc/pf.conf 2>/dev/null || true

    # Aufräumen
    rm -f "$LOCKFILE"
    rm -f "$PF_CONF"

    log ""
    log "${GREEN}Lockdown DEAKTIVIERT. Netzwerk ist wiederhergestellt.${NC}"
}

show_status() {
    echo ""
    if [[ -f "$LOCKFILE" ]]; then
        local activated_at
        activated_at=$(head -1 "$LOCKFILE")
        echo -e "${RED}Status: LOCKDOWN AKTIV${NC}"
        echo -e "Aktiviert: $activated_at"
    else
        echo -e "${GREEN}Status: Normal (kein Lockdown)${NC}"
    fi

    echo ""
    echo -e "${BLUE}Aktuelle pf-Regeln:${NC}"
    pfctl -sr 2>/dev/null || echo "(pf nicht aktiv)"

    echo ""
    echo -e "${BLUE}pf-Status:${NC}"
    pfctl -si 2>/dev/null | head -5

    echo ""
    echo -e "${BLUE}Claude Code Konnektivitätstest:${NC}"
    if curl -sS --connect-timeout 5 -o /dev/null -w "%{http_code}" https://api.anthropic.com 2>/dev/null | grep -qE "^[245]"; then
        echo -e "${GREEN}  api.anthropic.com: erreichbar${NC}"
    else
        echo -e "${RED}  api.anthropic.com: NICHT erreichbar${NC}"
    fi

    # Gegenprobe: anderer Host sollte blockiert sein
    if [[ -f "$LOCKFILE" ]]; then
        if curl -sS --connect-timeout 3 -o /dev/null https://www.google.com 2>/dev/null; then
            echo -e "${YELLOW}  google.com: erreichbar (Lockdown möglicherweise undicht!)${NC}"
        else
            echo -e "${GREEN}  google.com: blockiert (Lockdown funktioniert)${NC}"
        fi
    fi
}

refresh_ips() {
    check_root

    if [[ ! -f "$LOCKFILE" ]]; then
        log "${YELLOW}Kein aktiver Lockdown. Nichts zu aktualisieren.${NC}"
        exit 1
    fi

    log "${BLUE}Aktualisiere Anthropic-IPs...${NC}"
    generate_pf_rules
    pfctl -F all 2>/dev/null || true
    pfctl -f "$PF_CONF" 2>/dev/null
    pfctl -e 2>/dev/null || true
    log "${GREEN}IPs aktualisiert und Regeln neu geladen.${NC}"
}

show_help() {
    echo ""
    echo -e "${BLUE}network-lockdown.sh — Emergency Network Lockdown für macOS${NC}"
    echo ""
    echo "Blockiert den gesamten Netzwerkverkehr außer Claude Code CLI."
    echo "Nutzt macOS pfctl (Packet Filter)."
    echo ""
    echo -e "Verwendung: ${GREEN}sudo $0 <befehl>${NC}"
    echo ""
    echo "  on       Lockdown aktivieren"
    echo "  off      Lockdown deaktivieren, Netzwerk wiederherstellen"
    echo "  status   Aktuellen Status und Regeln anzeigen"
    echo "  refresh  Anthropic-IPs neu auflösen (bei CDN-Wechsel)"
    echo "  rules    Aktuelle Regeln anzeigen (ohne Aktivierung)"
    echo "  help     Diese Hilfe anzeigen"
    echo ""
    echo -e "${YELLOW}Hinweis: Erfordert root-Rechte (sudo).${NC}"
    echo ""
}

show_rules() {
    generate_pf_rules
    echo ""
    echo -e "${BLUE}Generierte Regeln:${NC}"
    cat "$PF_CONF"
    rm -f "$PF_CONF"
}

# === Main ===
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
        echo -e "${RED}Unbekannter Befehl: $1${NC}"
        show_help
        exit 1
        ;;
esac
