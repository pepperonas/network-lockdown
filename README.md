<p align="center">
  <img src="artwork/banner.png" alt="Network Lockdown — AI-assisted Incident Response" width="100%">
</p>

<h1 align="center">Network Lockdown</h1>

<p align="center">
  <strong>Kernel-level emergency network isolation with AI-assisted incident response</strong>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/github/license/pepperonas/network-lockdown?style=flat-square" alt="License"></a>
  <img src="https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows-blue?style=flat-square" alt="Platform">
  <img src="https://img.shields.io/badge/firewall-kernel--level-critical?style=flat-square&color=red" alt="Kernel-Level">
  <img src="https://img.shields.io/badge/AI-Claude%20Opus%204.6-blueviolet?style=flat-square" alt="Claude Opus 4.6">
  <img src="https://img.shields.io/badge/use%20case-incident%20response-orange?style=flat-square" alt="Incident Response">
  <a href="https://github.com/pepperonas/network-lockdown/stargazers"><img src="https://img.shields.io/github/stars/pepperonas/network-lockdown?style=flat-square" alt="Stars"></a>
</p>

---

## Übersicht

Notfall-Netzwerk-Lockdown fuer macOS, Linux und Windows. Bei einem Sicherheitsvorfall wird der gesamte Netzwerkverkehr auf Kernel-Ebene blockiert — **mit einer Ausnahme: Claude Code CLI bleibt online**. Damit kannst du den Rechner isolieren und trotzdem mit KI-Unterstuetzung (Claude Opus 4.6) forensische Analyse betreiben, Schadcode identifizieren und das System bereinigen.

Im aktivierten Zustand ist erlaubt:

- Claude Code CLI-Verbindungen zur Anthropic API (api.anthropic.com, Port 443 TLS)
- Localhost/Loopback-Verkehr
- DNS-Anfragen (notwendig fuer IP-Aufloesung)
- Rueckpakete etablierter Verbindungen

Alles andere wird blockiert — Browser, SSH, Updates, C2-Callbacks, Reverse Shells, Datenexfiltration.

## Use Case: Incident Response mit KI-Unterstützung

### Das Problem

Bei einem Sicherheitsvorfall lautet die erste Regel: **den Rechner sofort vom Netz nehmen**, um weiteren Schaden zu verhindern. Kein Datenabfluss, keine Lateral Movement, keine Command-and-Control-Kommunikation.

Aber dann stehst du vor einem isolierten Rechner und musst alleine herausfinden, was passiert ist. Forensische Analyse, Schadcode identifizieren, Logs auswerten, Backdoors finden, kompromittierte Dateien sicher löschen — das alles unter Zeitdruck und ohne Hilfe.

### Die Lösung

Diese Skripte nehmen den Rechner vom Netz, lassen aber **eine einzige Verbindung offen: Claude Code CLI** zur Anthropic API.

Claude Code (empfohlen: Opus 4.6) ist ein vollwertiger KI-Agent im Terminal. Er kann Dateien lesen, erstellen, durchsuchen, analysieren und bearbeiten. Damit hast du nach dem Lockdown einen KI-gestützten Incident-Response-Assistenten direkt auf dem betroffenen System:

**1. Netzwerkisolation (Lockdown aktivieren)**
```bash
sudo ./network-lockdown.sh on
```
Ab jetzt kann kein Prozess mehr nach aussen kommunizieren — kein Datenabfluss, kein C2-Callback, keine Exfiltration. Nur Claude Code CLI bleibt online.

**2. Forensische Analyse mit Claude Code**
```
> "Durchsuche /var/log auf verdaechtige SSH-Logins der letzten 48 Stunden"
> "Finde alle kuerzlich geaenderten Dateien in /etc und /usr/local/bin"
> "Analysiere diese Binary auf bekannte Malware-Patterns"
> "Zeige alle aktiven Cronjobs und systemd Timer — gibt es unbekannte Eintraege?"
> "Pruefe alle offenen Ports und die zugehoerigen Prozesse"
```

**3. Schadcode identifizieren und beseitigen**
```
> "Diese Datei sieht nach einer Reverse Shell aus — analysiere den Code"
> "Finde alle Dateien die von diesem User in den letzten 24h erstellt wurden"
> "Secure-erase der kompromittierten Dateien mit shred"
> "Pruefe ob authorized_keys manipuliert wurde"
```

**4. System haerten und Lockdown aufheben**
```
> "Erstelle ein Skript das alle gefundenen IOCs (Indicators of Compromise) dokumentiert"
> "Setze die SSH-Konfiguration auf sichere Defaults zurueck"
```
```bash
sudo ./network-lockdown.sh off
```

### Warum das funktioniert

- **Vollstaendige Netzwerkisolation** auf Kernel-Ebene — kein Prozess kann das umgehen
- **Claude Code CLI braucht nur HTTPS zu api.anthropic.com** — eine einzige, verschluesselte Verbindung
- **Claude Opus 4.6 analysiert beliebige Dateien**, Logs, Binaries und Konfigurationen direkt im Terminal
- **Kein zweiter Rechner noetig** — die KI laeuft remote bei Anthropic, du brauchst nur das Terminal
- **Angreifer verlieren jede Verbindung** — C2-Server, Exfiltrations-Kanaele, Reverse Shells werden sofort gekappt

Das Ergebnis: Du hast einen forensisch isolierten Rechner mit einem KI-Experten an deiner Seite.

---

## Funktionsweise: Kernel-Level Filtering

**Wichtig:** Alle drei Skripte arbeiten auf **Kernel-Ebene**.

Die Paketfilterung erfolgt nicht im Userspace, sondern direkt im Betriebssystem-Kernel, bevor Pakete das Netzwerk-Interface erreichen oder an Anwendungen weitergeleitet werden.

### Architektur-Überblick

```mermaid
graph TD
    subgraph OUT["AUSGEHEND"]
        A["App sendet Paket"]:::node --> B["Kernel Network Stack"]:::node
        B --> D{"FIREWALL\nPF / Netfilter / WFP"}:::fw

        D -- "Anthropic API :443" --> PASS1["PASS"]:::pass
        D -- "DNS :53" --> PASS1
        D -- "Loopback" --> PASS1
        D -- "Alles andere" --> DROP1["DROP"]:::drop

        PASS1 --> NET["Netzwerk"]:::node
    end

    subgraph IN["EINGEHEND"]
        NET2["Netzwerk"]:::node --> J{"FIREWALL\nPF / Netfilter / WFP"}:::fw

        J -- "Etablierte Verbindung" --> PASS2["PASS"]:::pass
        J -- "Alles andere" --> DROP2["DROP"]:::drop

        PASS2 --> APP["Anwendung"]:::node
    end

    classDef node fill:#1a1a2e,stroke:#555,color:#e0e0e0
    classDef fw fill:#0d47a1,stroke:#1565c0,color:#ffffff
    classDef pass fill:#1b5e20,stroke:#2e7d32,color:#ffffff
    classDef drop fill:#b71c1c,stroke:#c62828,color:#ffffff
```

### Paket-Flow im Detail

1. **Anwendung sendet Paket** (z.B. Browser ruft google.com auf)
2. **System Call** übergibt Paket an Kernel
3. **Kernel Network Stack** empfängt Paket
4. **Firewall-Filter** (PF/Netfilter/WFP) interceptiert das Paket
5. **Regelauswertung:**
   - Ziel = Anthropic API IPs + Port 443? → **PASS**
   - Ziel = DNS-Server + Port 53? → **PASS**
   - Ziel = 127.0.0.1 / ::1? → **PASS**
   - Sonst → **DROP** (ohne ICMP-Antwort)
6. Erlaubte Pakete erreichen das Network Interface

**Ergebnis:** Blockierte Pakete werden niemals gesendet. Die Anwendung erhält einen Timeout.

## Plattform-spezifische Implementierung

### macOS: `network-lockdown.sh`

**Technologie:** Packet Filter (PF)

- **Kernel-Framework:** PF ist von OpenBSD portiert und in den XNU-Kernel integriert
- **Kernel-Level:** Ja, PF ist ein Kernel-Modul, das direkt im Netzwerk-Stack arbeitet
- **Userspace-Tool:** `pfctl` konfiguriert die Kernel-Rules
- **Regel-Speicherort:** `/etc/pf.anchors/claude-lockdown`
- **Backup-Mechanismus:** `pfctl -sr` sichert aktuelle Rules, Wiederherstellung via `/etc/pf.conf.bak`
- **Voraussetzungen:** Keine (pfctl ist in macOS integriert)

**Besonderheiten:**
- Nutzt PF-Anchors für saubere Isolation der Rules
- Automatische Erkennung von Dual-Stack (IPv4/IPv6)
- Benötigt sudo-Rechte

### Linux: `network-lockdown-linux.sh`

**Technologie:** iptables/ip6tables + Netfilter

- **Kernel-Framework:** Netfilter ist fest im Linux-Kernel integriert
- **Kernel-Level:** Ja, Netfilter verwendet Kernel-Hooks an 5 Stellen:
  - `NF_INET_PRE_ROUTING` (vor Routing-Entscheidung)
  - `NF_INET_LOCAL_IN` (zu lokaler Anwendung)
  - `NF_INET_FORWARD` (Weiterleitung)
  - `NF_INET_LOCAL_OUT` (von lokaler Anwendung)
  - `NF_INET_POST_ROUTING` (nach Routing-Entscheidung)
- **Userspace-Tools:** `iptables`, `ip6tables` konfigurieren Netfilter
- **Connection Tracking:** `conntrack` Kernel-Modul für Stateful Filtering
- **Backup-Mechanismus:** `iptables-save` / `iptables-restore`
- **DNS-Erkennung:** `resolvectl` oder Fallback auf `/etc/resolv.conf`

**Besonderheiten:**
- ICMPv6 explizit erlaubt (für IPv6 Neighbor Discovery Protocol)
- Separate IPv4/IPv6-Regelsätze
- Benötigt root-Rechte

**Voraussetzungen:**
```bash
# Debian/Ubuntu
sudo apt-get install iptables dnsutils curl

# RHEL/CentOS/Fedora
sudo dnf install iptables bind-utils curl
```

### Windows: `network-lockdown-windows.ps1`

**Technologie:** Windows Filtering Platform (WFP)

- **Kernel-Framework:** WFP ist in `netio.sys` implementiert (Kernel-Mode-Treiber)
- **Kernel-Level:** Ja, WFP arbeitet in den NDIS/TDI-Schichten des Netzwerk-Stacks
- **Userspace-Tools:** PowerShell `New-NetFirewallRule`, `netsh advfirewall`
- **Regel-Identifikation:** Präfix "Claude-Lockdown-" für alle Rules
- **Backup-Mechanismus:** `netsh advfirewall export` (natives .wfw-Format)
- **DNS-Auflösung:** PowerShell `Resolve-DnsName` Cmdlet

**Besonderheiten:**
- Nutzt Windows Firewall API
- Separate Rules für IPv4/IPv6
- Automatische Profil-Erkennung (Domain/Private/Public)
- Benötigt Administrator-Rechte

**Voraussetzungen:**
- PowerShell 5.1 oder höher
- Windows 10/11 oder Windows Server 2016+

## Verwendung

### macOS und Linux

```bash
# Lockdown aktivieren
sudo ./network-lockdown.sh on

# Status prüfen
sudo ./network-lockdown.sh status

# IP-Liste aktualisieren (falls Anthropic CDN sich ändert)
sudo ./network-lockdown.sh refresh

# Aktuelle Rules anzeigen
sudo ./network-lockdown.sh rules

# Lockdown deaktivieren
sudo ./network-lockdown.sh off

# Hilfe anzeigen
./network-lockdown.sh help
```

### Windows

```powershell
# PowerShell als Administrator öffnen

# Lockdown aktivieren
.\network-lockdown-windows.ps1 on

# Status prüfen
.\network-lockdown-windows.ps1 status

# IP-Liste aktualisieren
.\network-lockdown-windows.ps1 refresh

# Aktuelle Rules anzeigen
.\network-lockdown-windows.ps1 rules

# Lockdown deaktivieren
.\network-lockdown-windows.ps1 off

# Hilfe anzeigen
.\network-lockdown-windows.ps1 help
```

## Befehls-Referenz

| Befehl | Beschreibung |
|--------|--------------|
| `on` | Aktiviert den Lockdown, erstellt Backup der aktuellen Firewall-Rules |
| `off` | Deaktiviert den Lockdown, stellt vorherige Rules wieder her |
| `status` | Zeigt aktuellen Status (aktiv/inaktiv) und letzte Aktivierung |
| `refresh` | Aktualisiert Anthropic IP-Adressen, reaktiviert Lockdown automatisch |
| `rules` | Zeigt alle aktiven Lockdown-Rules im Detail |
| `help` | Zeigt Verwendungshinweise |

## Erlaubter Netzwerkverkehr

### Immer erlaubt

- **Loopback:** 127.0.0.0/8, ::1/128
- **DNS:** Port 53 (TCP/UDP) zu System-DNS-Servern
- **Established Connections:** Rückpakete bereits etablierter Verbindungen
- **ICMPv6** (nur Linux): Neighbor Discovery Protocol

### Nur zu Anthropic API

- **Protokoll:** HTTPS (TCP Port 443)
- **Ziel:** Alle IP-Adressen, die `api.anthropic.com` auflöst
- **Richtung:** Nur ausgehend (outbound)

### Alles andere

**Blockiert** (ohne Antwort an Absender)

## Sicherheitsaspekte

### IP-Auflösung zur Aktivierungszeit

Die Anthropic API IPs werden beim Ausführen von `on` oder `refresh` via DNS aufgelöst:

```bash
# macOS/Linux
dig +short api.anthropic.com A
dig +short api.anthropic.com AAAA

# Windows
Resolve-DnsName api.anthropic.com
```

**Wichtig:** Wenn Anthropic seine CDN-IPs ändert, muss `refresh` ausgeführt werden.

### DNS als Angriffsfläche

DNS-Verkehr ist erlaubt, da er für die IP-Auflösung notwendig ist. Dies ist eine minimale Angriffsfläche:

- DNS-Spoofing könnte theoretisch falsche IPs liefern
- **Mitigation:** Claude Code CLI verwendet TLS-Zertifikatsprüfung
- Nur `api.anthropic.com` wird aufgelöst, nicht beliebige Domains

### Lockfile-Schutz

- Verhindert versehentliche Doppel-Aktivierung
- Speicherort: `/tmp/claude-lockdown.lock` (macOS/Linux)
- Wird bei `off` automatisch entfernt

### Backup und Wiederherstellung

**macOS:**
```bash
# Backup
pfctl -sr > /etc/pf.conf.bak

# Restore
pfctl -f /etc/pf.conf.bak
```

**Linux:**
```bash
# Backup
iptables-save > /etc/iptables.backup
ip6tables-save > /etc/ip6tables.backup

# Restore
iptables-restore < /etc/iptables.backup
ip6tables-restore < /etc/ip6tables.backup
```

**Windows:**
```powershell
# Backup
netsh advfirewall export "C:\Windows\Temp\firewall-backup.wfw"

# Restore
netsh advfirewall import "C:\Windows\Temp\firewall-backup.wfw"
```

### Berechtigungen

Alle Skripte benötigen erhöhte Rechte:

- **macOS/Linux:** `sudo` (root)
- **Windows:** Administrator (elevated PowerShell)

**Grund:** Firewall-Konfiguration ist eine privilegierte Operation, da sie die Kernel-Sicherheitsmechanismen modifiziert.

## Technische Details: Kernel-Hooks

### macOS (PF)

PF integriert sich in den XNU Kernel Network Stack:

```
Application → BSD Socket Layer → Network Layer (PF Hook) → Link Layer → Hardware
```

PF-Regeln werden in Kernel-Memory gespeichert und von `pfctl` via ioctl() Systemcalls konfiguriert.

### Linux (Netfilter)

Netfilter Hooks in der Kernel Network Pipeline:

```
Packet arrives → PRE_ROUTING → routing decision → FORWARD / LOCAL_IN
Packet sent → LOCAL_OUT → routing decision → POST_ROUTING → Network Interface
```

Jede Hook-Position kann Pakete ACCEPT, DROP oder REJECT.

### Windows (WFP)

WFP Layering im Windows Network Stack:

```
Application → Winsock → AFD.sys → TCP/IP Stack → WFP Callout Drivers → NDIS → NIC Driver
```

WFP Filter werden als Kernel-Mode-Objekte registriert und vom Filter Engine evaluiert.

## Fehlerbehebung

### "Already active" beim Start

**Ursache:** Lockfile existiert noch
```bash
# macOS/Linux
sudo rm /tmp/claude-lockdown.lock
sudo ./network-lockdown.sh on
```

### "Permission denied"

**Ursache:** Fehlende Admin-Rechte
```bash
# Immer mit sudo/Administrator ausführen
sudo ./network-lockdown.sh on
```

### Claude Code CLI kann nicht verbinden

1. Status prüfen: `sudo ./network-lockdown.sh status`
2. IPs aktualisieren: `sudo ./network-lockdown.sh refresh`
3. Rules prüfen: `sudo ./network-lockdown.sh rules`
4. Falls weiterhin Probleme: Lockdown deaktivieren und manuell testen

### DNS-Auflösung schlägt fehl

**Linux:** Prüfen, ob `dig` installiert ist
```bash
sudo apt-get install dnsutils
```

**Windows:** Prüfen, ob DNS-Client-Service läuft
```powershell
Get-Service Dnscache | Start-Service
```

## Performance-Hinweise

- **Overhead:** Kernel-Level-Filtering hat minimalen Performance-Impact (<1% CPU)
- **Latenz:** Keine messbare Latenz für erlaubte Verbindungen
- **Memory:** Rules belegen ~4-8 KB Kernel-Memory
- **Skalierung:** Bis zu 50 IP-Adressen problemlos handhabbar

## Lizenz und Haftung

Diese Skripte werden ohne Gewährleistung bereitgestellt. Testen Sie sie in einer sicheren Umgebung, bevor Sie sie produktiv einsetzen.

**Warnung:** Ein aktiver Lockdown blockiert alle Netzwerkverbindungen außer Claude Code CLI. SSH-Verbindungen, Updates, Browser etc. funktionieren nicht.

## Version

- **macOS Script:** network-lockdown.sh
- **Linux Script:** network-lockdown-linux.sh
- **Windows Script:** network-lockdown-windows.ps1
- **Dokumentation:** README-network-lockdown.md (2026-02-20)
