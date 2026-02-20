#Requires -RunAsAdministrator
# =============================================================================
# network-lockdown-windows.ps1 — Emergency Network Lockdown for Windows
# Blocks all traffic except Claude Code CLI (Anthropic API)
# Uses Windows Firewall (NetSecurity / advfirewall)
# =============================================================================

param(
    [Parameter(Position = 0)]
    [ValidateSet("on", "off", "status", "refresh", "rules", "help")]
    [string]$Action = "help"
)

$ErrorActionPreference = "Stop"

$VERSION = "1.1.0"

$LOCKFILE = "$env:TEMP\claude-lockdown.active"
$LOG_FILE = "$env:TEMP\claude-lockdown.log"
$BACKUP_FILE = "$env:TEMP\claude-lockdown-backup.wfw"
$RULE_PREFIX = "Claude-Lockdown"

# Farben
function Write-Log {
    param([string]$Message, [string]$Color = "White")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $LOG_FILE -Value "[$timestamp] $Message" -ErrorAction SilentlyContinue
    Write-Host $Message -ForegroundColor $Color
}

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Anthropic-Domains aufloesen
function Resolve-AnthropicIPs {
    $domains = @(
        "api.anthropic.com"
        "statsig.anthropic.com"
        "api.statsig.com"
    )

    $ipv4 = @()
    $ipv6 = @()

    foreach ($domain in $domains) {
        try {
            $records = Resolve-DnsName -Name $domain -ErrorAction SilentlyContinue
            foreach ($record in $records) {
                if ($record.Type -eq "A" -and $record.IPAddress) {
                    $ipv4 += $record.IPAddress
                }
                elseif ($record.Type -eq "AAAA" -and $record.IPAddress) {
                    $ipv6 += $record.IPAddress
                }
            }
        }
        catch {
            Write-Log "  Warnung: $domain konnte nicht aufgeloest werden" "Yellow"
        }
    }

    $ipv4 = $ipv4 | Sort-Object -Unique
    $ipv6 = $ipv6 | Sort-Object -Unique

    return @{ IPv4 = $ipv4; IPv6 = $ipv6 }
}

# DNS-Server des Systems ermitteln
function Get-SystemDnsServers {
    $dnsServers = @()
    try {
        $adapters = Get-DnsClientServerAddress -ErrorAction SilentlyContinue |
            Where-Object { $_.ServerAddresses.Count -gt 0 }
        foreach ($adapter in $adapters) {
            $dnsServers += $adapter.ServerAddresses
        }
    }
    catch {
        # Fallback
        $dnsServers = @("8.8.8.8", "8.8.4.4", "1.1.1.1")
    }
    return $dnsServers | Sort-Object -Unique
}

# Alle Lockdown-Regeln entfernen
function Remove-LockdownRules {
    Get-NetFirewallRule -DisplayName "$RULE_PREFIX*" -ErrorAction SilentlyContinue |
        Remove-NetFirewallRule -ErrorAction SilentlyContinue
}

function Enable-Lockdown {
    if (-not (Test-Administrator)) {
        Write-Log "Dieses Script benoetigt Administrator-Rechte." "Red"
        Write-Log "Starte PowerShell als Administrator und fuehre es erneut aus." "Red"
        return
    }

    if (Test-Path $LOCKFILE) {
        Write-Log "Lockdown ist bereits aktiv. Zum Neustart erst deaktivieren: .\$($MyInvocation.ScriptName) off" "Yellow"
        return
    }

    Write-Log "=== NETWORK LOCKDOWN — AKTIVIERUNG ===" "Yellow"
    Write-Log ""

    # Aktuelle Firewall-Konfiguration sichern
    Write-Log "Sichere aktuelle Firewall-Regeln..." "Cyan"
    try {
        netsh advfirewall export $BACKUP_FILE | Out-Null
        Write-Log "Backup gespeichert: $BACKUP_FILE" "Cyan"
    }
    catch {
        Write-Log "Warnung: Backup konnte nicht erstellt werden" "Yellow"
    }

    # IPs aufloesen
    Write-Log "Loese Anthropic-Domains auf..." "Cyan"
    $ips = Resolve-AnthropicIPs

    if ($ips.IPv4.Count -eq 0 -and $ips.IPv6.Count -eq 0) {
        Write-Log "Keine IPs aufgeloest — Abbruch. Pruefe deine DNS-Konfiguration." "Red"
        return
    }

    Write-Log "Aufgeloeste IPv4: $($ips.IPv4 -join ', ')" "Green"
    if ($ips.IPv6.Count -gt 0) {
        Write-Log "Aufgeloeste IPv6: $($ips.IPv6 -join ', ')" "Green"
    }

    $dnsServers = Get-SystemDnsServers
    Write-Log "DNS-Server: $($dnsServers -join ', ')" "Cyan"

    # Bestehende Lockdown-Regeln entfernen (falls vorhanden)
    Remove-LockdownRules

    Write-Log "Erstelle Firewall-Regeln..." "Cyan"

    # ──────────────────────────────────────────────
    # Schritt 1: Alles blockieren (niedrige Prioritaet)
    # ──────────────────────────────────────────────

    New-NetFirewallRule `
        -DisplayName "$RULE_PREFIX - Block All Outbound" `
        -Direction Outbound -Action Block `
        -Protocol Any -Enabled True `
        -Description "Blockiert gesamten ausgehenden Verkehr" | Out-Null

    New-NetFirewallRule `
        -DisplayName "$RULE_PREFIX - Block All Inbound" `
        -Direction Inbound -Action Block `
        -Protocol Any -Enabled True `
        -Description "Blockiert gesamten eingehenden Verkehr" | Out-Null

    # ──────────────────────────────────────────────
    # Schritt 2: Loopback erlauben
    # ──────────────────────────────────────────────

    New-NetFirewallRule `
        -DisplayName "$RULE_PREFIX - Allow Loopback Out" `
        -Direction Outbound -Action Allow `
        -RemoteAddress 127.0.0.0/8,::1 `
        -Enabled True | Out-Null

    New-NetFirewallRule `
        -DisplayName "$RULE_PREFIX - Allow Loopback In" `
        -Direction Inbound -Action Allow `
        -RemoteAddress 127.0.0.0/8,::1 `
        -Enabled True | Out-Null

    # ──────────────────────────────────────────────
    # Schritt 3: DNS erlauben
    # ──────────────────────────────────────────────

    $dnsIPv4 = $dnsServers | Where-Object { $_ -notmatch ":" }
    $dnsIPv6 = $dnsServers | Where-Object { $_ -match ":" }

    if ($dnsIPv4.Count -gt 0) {
        New-NetFirewallRule `
            -DisplayName "$RULE_PREFIX - Allow DNS UDP v4" `
            -Direction Outbound -Action Allow `
            -Protocol UDP -RemotePort 53 `
            -RemoteAddress ($dnsIPv4 -join ",") `
            -Enabled True | Out-Null

        New-NetFirewallRule `
            -DisplayName "$RULE_PREFIX - Allow DNS TCP v4" `
            -Direction Outbound -Action Allow `
            -Protocol TCP -RemotePort 53 `
            -RemoteAddress ($dnsIPv4 -join ",") `
            -Enabled True | Out-Null
    }

    if ($dnsIPv6.Count -gt 0) {
        New-NetFirewallRule `
            -DisplayName "$RULE_PREFIX - Allow DNS UDP v6" `
            -Direction Outbound -Action Allow `
            -Protocol UDP -RemotePort 53 `
            -RemoteAddress ($dnsIPv6 -join ",") `
            -Enabled True | Out-Null

        New-NetFirewallRule `
            -DisplayName "$RULE_PREFIX - Allow DNS TCP v6" `
            -Direction Outbound -Action Allow `
            -Protocol TCP -RemotePort 53 `
            -RemoteAddress ($dnsIPv6 -join ",") `
            -Enabled True | Out-Null
    }

    # ──────────────────────────────────────────────
    # Schritt 4: Anthropic API erlauben
    # ──────────────────────────────────────────────

    if ($ips.IPv4.Count -gt 0) {
        New-NetFirewallRule `
            -DisplayName "$RULE_PREFIX - Allow Anthropic HTTPS v4" `
            -Direction Outbound -Action Allow `
            -Protocol TCP -RemotePort 443 `
            -RemoteAddress ($ips.IPv4 -join ",") `
            -Enabled True | Out-Null

        # Eingehende Antworten fuer etablierte Verbindungen
        New-NetFirewallRule `
            -DisplayName "$RULE_PREFIX - Allow Anthropic Response v4" `
            -Direction Inbound -Action Allow `
            -Protocol TCP -LocalPort 1024-65535 `
            -RemoteAddress ($ips.IPv4 -join ",") `
            -Enabled True | Out-Null
    }

    if ($ips.IPv6.Count -gt 0) {
        New-NetFirewallRule `
            -DisplayName "$RULE_PREFIX - Allow Anthropic HTTPS v6" `
            -Direction Outbound -Action Allow `
            -Protocol TCP -RemotePort 443 `
            -RemoteAddress ($ips.IPv6 -join ",") `
            -Enabled True | Out-Null

        New-NetFirewallRule `
            -DisplayName "$RULE_PREFIX - Allow Anthropic Response v6" `
            -Direction Inbound -Action Allow `
            -Protocol TCP -LocalPort 1024-65535 `
            -RemoteAddress ($ips.IPv6 -join ",") `
            -Enabled True | Out-Null
    }

    # ──────────────────────────────────────────────
    # Schritt 5: DNS-Antworten erlauben
    # ──────────────────────────────────────────────

    if ($dnsIPv4.Count -gt 0) {
        New-NetFirewallRule `
            -DisplayName "$RULE_PREFIX - Allow DNS Response v4" `
            -Direction Inbound -Action Allow `
            -Protocol UDP -LocalPort 1024-65535 `
            -RemoteAddress ($dnsIPv4 -join ",") `
            -Enabled True | Out-Null
    }

    if ($dnsIPv6.Count -gt 0) {
        New-NetFirewallRule `
            -DisplayName "$RULE_PREFIX - Allow DNS Response v6" `
            -Direction Inbound -Action Allow `
            -Protocol UDP -LocalPort 1024-65535 `
            -RemoteAddress ($dnsIPv6 -join ",") `
            -Enabled True | Out-Null
    }

    # ──────────────────────────────────────────────

    # Lockfile erstellen
    @(
        (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        $BACKUP_FILE
        ($ips.IPv4 -join ",")
        ($ips.IPv6 -join ",")
    ) | Set-Content $LOCKFILE

    Write-Log "" "White"
    Write-Log "Lockdown AKTIV." "Green"
    Write-Log "  Erlaubt:   Anthropic API (Claude Code CLI)" "Green"
    Write-Log "  Erlaubt:   DNS-Aufloesung" "Green"
    Write-Log "  Erlaubt:   Localhost/Loopback" "Green"
    Write-Log "  Blockiert: Gesamter uebriger Netzwerkverkehr" "Red"
    Write-Log "" "White"
    Write-Log "Deaktivieren mit: .\network-lockdown-windows.ps1 off" "Cyan"
    Write-Log "Status pruefen:   .\network-lockdown-windows.ps1 status" "Cyan"
    Write-Log "IPs aktualisieren: .\network-lockdown-windows.ps1 refresh" "Cyan"
    Write-Log "" "White"
    Write-Log "Forensische Analyse-Guideline:" "Yellow"
    Write-Log "  https://github.com/pepperonas/network-lockdown/blob/main/INCIDENT-RESPONSE-GUIDE.md" "Cyan"
}

function Disable-Lockdown {
    if (-not (Test-Administrator)) {
        Write-Log "Dieses Script benoetigt Administrator-Rechte." "Red"
        return
    }

    Write-Log "=== NETWORK LOCKDOWN — DEAKTIVIERUNG ===" "Yellow"
    Write-Log ""

    # Lockdown-Regeln entfernen
    Remove-LockdownRules
    Write-Log "Lockdown-Regeln entfernt" "Cyan"

    # Backup wiederherstellen
    $backupPath = $null
    if (Test-Path $LOCKFILE) {
        $lines = Get-Content $LOCKFILE
        if ($lines.Count -ge 2) {
            $backupPath = $lines[1]
        }
    }

    if ($backupPath -and (Test-Path $backupPath)) {
        try {
            netsh advfirewall import $backupPath | Out-Null
            Write-Log "Firewall-Regeln aus Backup wiederhergestellt" "Cyan"
        }
        catch {
            Write-Log "Warnung: Backup konnte nicht importiert werden. Standard-Firewall aktiv." "Yellow"
        }
    }
    else {
        Write-Log "Kein Backup gefunden. Firewall bleibt im aktuellen Zustand (ohne Lockdown-Regeln)." "Yellow"
    }

    # Aufraeumen
    Remove-Item -Path $LOCKFILE -Force -ErrorAction SilentlyContinue

    Write-Log "" "White"
    Write-Log "Lockdown DEAKTIVIERT. Netzwerk ist wiederhergestellt." "Green"
}

function Show-Status {
    Write-Host ""
    if (Test-Path $LOCKFILE) {
        $lines = Get-Content $LOCKFILE
        Write-Host "Status: LOCKDOWN AKTIV" -ForegroundColor Red
        Write-Host "Aktiviert: $($lines[0])"
        if ($lines.Count -ge 3) {
            Write-Host "Erlaubte IPv4: $($lines[2])" -ForegroundColor DarkGray
        }
        if ($lines.Count -ge 4 -and $lines[3]) {
            Write-Host "Erlaubte IPv6: $($lines[3])" -ForegroundColor DarkGray
        }
    }
    else {
        Write-Host "Status: Normal (kein Lockdown)" -ForegroundColor Green
    }

    Write-Host ""
    Write-Host "Lockdown-Regeln:" -ForegroundColor Cyan
    $rules = Get-NetFirewallRule -DisplayName "$RULE_PREFIX*" -ErrorAction SilentlyContinue
    if ($rules) {
        $rules | Format-Table DisplayName, Direction, Action, Enabled -AutoSize
    }
    else {
        Write-Host "  Keine Lockdown-Regeln aktiv"
    }

    Write-Host ""
    Write-Host "Claude Code Konnektivitaetstest:" -ForegroundColor Cyan
    try {
        $response = Invoke-WebRequest -Uri "https://api.anthropic.com" -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
        Write-Host "  api.anthropic.com: erreichbar ($($response.StatusCode))" -ForegroundColor Green
    }
    catch {
        if ($_.Exception.Response) {
            Write-Host "  api.anthropic.com: erreichbar (HTTP-Antwort erhalten)" -ForegroundColor Green
        }
        else {
            Write-Host "  api.anthropic.com: NICHT erreichbar" -ForegroundColor Red
        }
    }

    if (Test-Path $LOCKFILE) {
        try {
            Invoke-WebRequest -Uri "https://www.google.com" -UseBasicParsing -TimeoutSec 3 -ErrorAction Stop | Out-Null
            Write-Host "  google.com: erreichbar (Lockdown moeglicherweise undicht!)" -ForegroundColor Yellow
        }
        catch {
            Write-Host "  google.com: blockiert (Lockdown funktioniert)" -ForegroundColor Green
        }
    }
}

function Update-IPs {
    if (-not (Test-Administrator)) {
        Write-Log "Dieses Script benoetigt Administrator-Rechte." "Red"
        return
    }

    if (-not (Test-Path $LOCKFILE)) {
        Write-Log "Kein aktiver Lockdown. Nichts zu aktualisieren." "Yellow"
        return
    }

    Write-Log "Aktualisiere Anthropic-IPs..." "Cyan"

    # Backup-Pfad merken
    $lines = Get-Content $LOCKFILE
    $backupPath = if ($lines.Count -ge 2) { $lines[1] } else { $null }

    # Lockfile entfernen und Lockdown neu aufbauen
    Remove-Item -Path $LOCKFILE -Force -ErrorAction SilentlyContinue
    Remove-LockdownRules
    Enable-Lockdown

    # Originalen Backup-Pfad wiederherstellen
    if ($backupPath -and (Test-Path $LOCKFILE)) {
        $newLines = Get-Content $LOCKFILE
        $newLines[1] = $backupPath
        $newLines | Set-Content $LOCKFILE
    }

    Write-Log "IPs aktualisiert und Regeln neu geladen." "Green"
}

function Show-Rules {
    Write-Host ""
    Write-Host "Aktuelle Lockdown-Firewall-Regeln:" -ForegroundColor Cyan
    Write-Host ""

    $rules = Get-NetFirewallRule -DisplayName "$RULE_PREFIX*" -ErrorAction SilentlyContinue
    if ($rules) {
        foreach ($rule in $rules) {
            Write-Host "[$($rule.Direction)] $($rule.DisplayName)" -ForegroundColor White
            Write-Host "  Action: $($rule.Action) | Enabled: $($rule.Enabled)" -ForegroundColor DarkGray

            $addressFilter = $rule | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue
            $portFilter = $rule | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue

            if ($addressFilter.RemoteAddress -and $addressFilter.RemoteAddress -ne "Any") {
                Write-Host "  Remote: $($addressFilter.RemoteAddress -join ', ')" -ForegroundColor DarkGray
            }
            if ($portFilter.RemotePort -and $portFilter.RemotePort -ne "Any") {
                Write-Host "  Port: $($portFilter.Protocol)/$($portFilter.RemotePort)" -ForegroundColor DarkGray
            }
            Write-Host ""
        }
    }
    else {
        Write-Host "  Keine Lockdown-Regeln vorhanden"
    }
}

function Show-Banner {
    $ver = "v$VERSION"
    $titleText = "NETWORK LOCKDOWN"
    $innerWidth = 58
    $titlePad = $innerWidth - 3 - $titleText.Length - $ver.Length - 3

    Write-Host ""
    Write-Host ("╔" + ("═" * $innerWidth) + "╗") -ForegroundColor Cyan
    Write-Host ("║" + (" " * $innerWidth) + "║") -ForegroundColor Cyan
    # Title
    Write-Host "║" -ForegroundColor Cyan -NoNewline
    Write-Host "   " -NoNewline
    Write-Host $titleText -ForegroundColor White -NoNewline
    Write-Host (" " * $titlePad) -NoNewline
    Write-Host $ver -ForegroundColor DarkGray -NoNewline
    Write-Host "   " -NoNewline
    Write-Host "║" -ForegroundColor Cyan
    # Separator
    Write-Host "║" -ForegroundColor Cyan -NoNewline
    Write-Host ("   " + ("━" * 52) + "   ") -ForegroundColor DarkGray -NoNewline
    Write-Host "║" -ForegroundColor Cyan
    # Description
    Write-Host "║" -ForegroundColor Cyan -NoNewline
    Write-Host ("   Kernel-level emergency network isolation" + (" " * 15)) -NoNewline
    Write-Host "║" -ForegroundColor Cyan
    # Platform
    Write-Host "║" -ForegroundColor Cyan -NoNewline
    Write-Host "   Platform: " -NoNewline
    Write-Host "Windows" -ForegroundColor Green -NoNewline
    Write-Host " " -NoNewline
    Write-Host "(WFP/NetSecurity)" -ForegroundColor DarkGray -NoNewline
    Write-Host (" " * 20) -NoNewline
    Write-Host "║" -ForegroundColor Cyan
    # Empty
    Write-Host ("║" + (" " * $innerWidth) + "║") -ForegroundColor Cyan
    # Developer
    Write-Host "║" -ForegroundColor Cyan -NoNewline
    Write-Host "   " -NoNewline
    Write-Host "Martin Pfeffer - celox.io" -ForegroundColor DarkGray -NoNewline
    Write-Host (" " * 30) -NoNewline
    Write-Host "║" -ForegroundColor Cyan
    # Empty
    Write-Host ("║" + (" " * $innerWidth) + "║") -ForegroundColor Cyan
    # Bottom
    Write-Host ("╚" + ("═" * $innerWidth) + "╝") -ForegroundColor Cyan
    Write-Host ""
}

function Show-Help {
    Write-Host ""
    Write-Host "network-lockdown-windows.ps1 — Emergency Network Lockdown fuer Windows" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Blockiert den gesamten Netzwerkverkehr ausser Claude Code CLI."
    Write-Host "Nutzt Windows Firewall (NetSecurity)."
    Write-Host ""
    Write-Host "Verwendung: " -NoNewline
    Write-Host ".\network-lockdown-windows.ps1 <befehl>" -ForegroundColor Green
    Write-Host ""
    Write-Host "  on       Lockdown aktivieren"
    Write-Host "  off      Lockdown deaktivieren, Netzwerk wiederherstellen"
    Write-Host "  status   Aktuellen Status und Regeln anzeigen"
    Write-Host "  refresh  Anthropic-IPs neu aufloesen (bei CDN-Wechsel)"
    Write-Host "  rules    Aktuelle Firewall-Regeln detailliert anzeigen"
    Write-Host "  help     Diese Hilfe anzeigen"
    Write-Host ""
    Write-Host "Hinweis: Erfordert Administrator-Rechte (Als Admin ausfuehren)." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Forensische Analyse-Guideline:" -ForegroundColor Yellow
    Write-Host "  https://github.com/pepperonas/network-lockdown/blob/main/INCIDENT-RESPONSE-GUIDE.md" -ForegroundColor Cyan
    Write-Host ""
}

# === Main ===
Show-Banner
switch ($Action) {
    "on"      { Enable-Lockdown }
    "off"     { Disable-Lockdown }
    "status"  { Show-Status }
    "refresh" { Update-IPs }
    "rules"   { Show-Rules }
    "help"    { Show-Help }
    default   { Show-Help }
}
