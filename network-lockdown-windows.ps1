#Requires -RunAsAdministrator
# =============================================================================
# network-lockdown-windows.ps1 — Emergency Network Lockdown for Windows
# Blocks all traffic except Claude Code CLI (Anthropic API)
# Uses Windows Firewall (NetSecurity / advfirewall)
# =============================================================================

param(
    [Parameter(Position = 0)]
    [ValidateSet("on", "off", "status", "refresh", "rules", "guide", "help")]
    [string]$Action = "help",

    [Alias("s")]
    [switch]$Strict
)

$ErrorActionPreference = "Stop"

$VERSION = "1.2.0"
$GITHUB_RAW = "https://github.com/pepperonas/network-lockdown/raw/main"

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

    # Append CIDR suffix so WFP treats every entry as a host address
    # (e.g. 34.128.128.0 without /32 is rejected as "network address")
    $ipv4 = @($ipv4 | ForEach-Object { if ($_ -notmatch "/") { "$_/32" } else { $_ } })
    $ipv6 = @($ipv6 | ForEach-Object { if ($_ -notmatch "/") { "$_/128" } else { $_ } })

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

# Alle Lockdown-Regeln entfernen (Host- + Hyper-V-Firewall)
function Remove-LockdownRules {
    Get-NetFirewallRule -DisplayName "$RULE_PREFIX*" -ErrorAction SilentlyContinue |
        Remove-NetFirewallRule -ErrorAction SilentlyContinue

    if (Get-Command Get-NetFirewallHyperVRule -ErrorAction SilentlyContinue) {
        Get-NetFirewallHyperVRule -DisplayName "$RULE_PREFIX*" -ErrorAction SilentlyContinue |
            Remove-NetFirewallHyperVRule -ErrorAction SilentlyContinue
    }
}

# Hyper-V-Firewall verfuegbar? (Win 11 22H2+ mit WSL 2.0.9+ oder neuerem Docker Desktop)
function Test-HyperVFirewallSupport {
    return [bool](Get-Command Get-NetFirewallHyperVVMSetting -ErrorAction SilentlyContinue)
}

# WSL Mirrored Networking Mode erkennen (.wslconfig).
# Im Mirrored-Mode teilt sich WSL2 den Host-Netzwerk-Stack statt eigenes
# vEthernet zu nutzen — Hyper-V-Firewall greift anders.
function Get-WSLNetworkingMode {
    $wslConfig = Join-Path $env:USERPROFILE ".wslconfig"
    if (-not (Test-Path $wslConfig)) { return "default (NAT)" }
    try {
        $content = Get-Content $wslConfig -Raw -ErrorAction Stop
        if ($content -match "(?im)^\s*networkingMode\s*=\s*(\S+)") {
            return $Matches[1].Trim()
        }
    }
    catch { }
    return "default (NAT)"
}

# Docker Desktop / WSL2 erkennen
function Test-DockerOrWSL {
    $found = $false
    if (Get-Process -Name "Docker Desktop" -ErrorAction SilentlyContinue) { $found = $true }
    if (Get-Process -Name "com.docker.backend" -ErrorAction SilentlyContinue) { $found = $true }
    if (Get-Process -Name "vmmem", "vmmemWSL" -ErrorAction SilentlyContinue) { $found = $true }
    if (Get-Service -Name "com.docker.service" -ErrorAction SilentlyContinue |
        Where-Object { $_.Status -eq "Running" }) { $found = $true }
    if (Get-Service -Name "LxssManager" -ErrorAction SilentlyContinue |
        Where-Object { $_.Status -eq "Running" }) { $found = $true }
    return $found
}

# Alle aktiven Hyper-V-VM-Creator-IDs auslesen.
# WSL: {40E0AC32-46A5-438A-A0B2-2B479E8F2E90}
# Docker Desktop / weitere VMs: eigene GUIDs
function Get-ActiveVMCreatorIds {
    if (-not (Test-HyperVFirewallSupport)) { return @() }
    try {
        return @(Get-NetFirewallHyperVVMSetting -PolicyStore ActiveStore -ErrorAction SilentlyContinue |
            ForEach-Object { $_.Name })
    }
    catch {
        return @()
    }
}

# Hyper-V-Firewall: Outbound auf Block setzen + Allow-Regeln fuer Anthropic/DNS.
# Wirkt fuer WSL2 + Docker Desktop (WSL2-backend & Hyper-V-backend),
# die sonst die Host-Windows-Firewall umgehen wuerden.
function Block-HyperVTraffic {
    param(
        [string[]]$AllowIPv4,
        [string[]]$AllowIPv6,
        [string[]]$DnsIPv4,
        [string[]]$DnsIPv6
    )

    if (-not (Test-HyperVFirewallSupport)) {
        Write-Log "Hyper-V-Firewall nicht verfuegbar (Win 11 22H2+ benoetigt)." "Yellow"
        if (Test-DockerOrWSL) {
            Write-Log "  WARNUNG: Docker/WSL2 laeuft! Lockdown wirkt NICHT auf Container/VMs." "Red"
            Write-Log "  Empfehlung: 'wsl --shutdown' und Docker Desktop beenden." "Red"
        }
        return
    }

    $wslMode = Get-WSLNetworkingMode
    if ($wslMode -eq "mirrored") {
        Write-Log "WSL Networking Mode: mirrored — Hyper-V-Regeln verhalten sich anders als NAT." "Yellow"
    }

    $vmCreatorIds = Get-ActiveVMCreatorIds
    if ($vmCreatorIds.Count -eq 0) {
        Write-Log "Keine Hyper-V-VMs/Container aktiv." "DarkGray"
        return
    }

    Write-Log "Konfiguriere Hyper-V-Firewall fuer $($vmCreatorIds.Count) VM-Creator(s)..." "Cyan"

    foreach ($vmId in $vmCreatorIds) {
        try {
            # Default Outbound Block fuer diese VM-Klasse
            Set-NetFirewallHyperVVMSetting -Name $vmId `
                -DefaultOutboundAction Block `
                -DefaultInboundAction Block `
                -ErrorAction Stop
            Write-Log "  VM $vmId : default outbound = Block" "DarkGray"
        }
        catch {
            Write-Log "  VM $vmId : konnte Default-Policy nicht setzen ($($_.Exception.Message))" "Yellow"
            continue
        }

        # Anthropic-Allow-Regeln pro VM-Creator
        if ($AllowIPv4.Count -gt 0) {
            New-NetFirewallHyperVRule `
                -Name "$RULE_PREFIX-HV-Anthropic-v4-$vmId" `
                -DisplayName "$RULE_PREFIX - HV Anthropic HTTPS v4" `
                -VMCreatorId $vmId `
                -Direction Outbound -Action Allow `
                -Protocol TCP -RemotePorts 443 `
                -RemoteAddresses $AllowIPv4 `
                -Enabled True -ErrorAction SilentlyContinue | Out-Null
        }
        if ($AllowIPv6.Count -gt 0) {
            New-NetFirewallHyperVRule `
                -Name "$RULE_PREFIX-HV-Anthropic-v6-$vmId" `
                -DisplayName "$RULE_PREFIX - HV Anthropic HTTPS v6" `
                -VMCreatorId $vmId `
                -Direction Outbound -Action Allow `
                -Protocol TCP -RemotePorts 443 `
                -RemoteAddresses $AllowIPv6 `
                -Enabled True -ErrorAction SilentlyContinue | Out-Null
        }

        # DNS-Allow pro VM-Creator
        if ($DnsIPv4.Count -gt 0) {
            New-NetFirewallHyperVRule `
                -Name "$RULE_PREFIX-HV-DNS-UDP-v4-$vmId" `
                -DisplayName "$RULE_PREFIX - HV DNS UDP v4" `
                -VMCreatorId $vmId `
                -Direction Outbound -Action Allow `
                -Protocol UDP -RemotePorts 53 `
                -RemoteAddresses $DnsIPv4 `
                -Enabled True -ErrorAction SilentlyContinue | Out-Null
            New-NetFirewallHyperVRule `
                -Name "$RULE_PREFIX-HV-DNS-TCP-v4-$vmId" `
                -DisplayName "$RULE_PREFIX - HV DNS TCP v4" `
                -VMCreatorId $vmId `
                -Direction Outbound -Action Allow `
                -Protocol TCP -RemotePorts 53 `
                -RemoteAddresses $DnsIPv4 `
                -Enabled True -ErrorAction SilentlyContinue | Out-Null
        }
        if ($DnsIPv6.Count -gt 0) {
            New-NetFirewallHyperVRule `
                -Name "$RULE_PREFIX-HV-DNS-UDP-v6-$vmId" `
                -DisplayName "$RULE_PREFIX - HV DNS UDP v6" `
                -VMCreatorId $vmId `
                -Direction Outbound -Action Allow `
                -Protocol UDP -RemotePorts 53 `
                -RemoteAddresses $DnsIPv6 `
                -Enabled True -ErrorAction SilentlyContinue | Out-Null
        }

        # Loopback-Verkehr innerhalb der VM erlauben
        New-NetFirewallHyperVRule `
            -Name "$RULE_PREFIX-HV-Loopback-$vmId" `
            -DisplayName "$RULE_PREFIX - HV Loopback" `
            -VMCreatorId $vmId `
            -Direction Outbound -Action Allow `
            -RemoteAddresses 127.0.0.0/8 `
            -Enabled True -ErrorAction SilentlyContinue | Out-Null
    }

    Write-Log "Hyper-V-Firewall: Container-/VM-Traffic auf Anthropic+DNS beschraenkt." "Green"
}

# Strict-Modus: Bestehende TCP-Verbindungen zu nicht-Anthropic-IPs zwangsweise
# schliessen via iphlpapi.dll!SetTcpEntry (gleiche API wie TCPView).
# Schliesst die TCP-Connection-Table-Eintraege, ohne Prozesse zu killen.
function Close-NonAllowedConnections {
    param(
        [string[]]$AllowedIPv4
    )

    # IPs ohne CIDR-Suffix fuer Vergleich
    $allowedHosts = @($AllowedIPv4 | ForEach-Object { ($_ -split "/")[0] })

    if (-not ([System.Management.Automation.PSTypeName]'NetLockdown.TcpKiller').Type) {
        Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
namespace NetLockdown {
    [StructLayout(LayoutKind.Sequential)]
    public struct MIB_TCPROW {
        public uint State;
        public uint LocalAddr;
        public uint LocalPort;
        public uint RemoteAddr;
        public uint RemotePort;
    }
    public static class TcpKiller {
        [DllImport("iphlpapi.dll", SetLastError=true)]
        public static extern int SetTcpEntry(ref MIB_TCPROW pTcprow);
        public const uint MIB_TCP_STATE_DELETE_TCB = 12;
    }
}
"@ -ErrorAction SilentlyContinue
    }

    $closed = 0
    $kept = 0
    try {
        $connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
        foreach ($conn in $connections) {
            $remote = $conn.RemoteAddress

            # Loopback skip
            if ($remote -eq "127.0.0.1" -or $remote -eq "::1" -or $remote.StartsWith("169.254.")) {
                continue
            }

            # IPv4 only fuer SetTcpEntry — IPv6-Killing braucht andere API
            if ($remote -notmatch "^\d+\.\d+\.\d+\.\d+$") {
                continue
            }

            if ($allowedHosts -contains $remote) {
                $kept++
                continue
            }

            # IP/Port in Network-Byte-Order packen
            try {
                $localAddr = [System.Net.IPAddress]::Parse($conn.LocalAddress).GetAddressBytes()
                $remoteAddr = [System.Net.IPAddress]::Parse($remote).GetAddressBytes()
                $row = New-Object NetLockdown.MIB_TCPROW
                $row.State = [NetLockdown.TcpKiller]::MIB_TCP_STATE_DELETE_TCB
                $row.LocalAddr = [BitConverter]::ToUInt32($localAddr, 0)
                $row.LocalPort = [System.Net.IPAddress]::HostToNetworkOrder([int16]$conn.LocalPort) -band 0xFFFF
                $row.RemoteAddr = [BitConverter]::ToUInt32($remoteAddr, 0)
                $row.RemotePort = [System.Net.IPAddress]::HostToNetworkOrder([int16]$conn.RemotePort) -band 0xFFFF
                $result = [NetLockdown.TcpKiller]::SetTcpEntry([ref]$row)
                if ($result -eq 0) { $closed++ }
            }
            catch {
                # einzelne Verbindung konnte nicht geschlossen werden — weiter
            }
        }
    }
    catch {
        Write-Log "  Strict-Modus: Get-NetTCPConnection fehlgeschlagen ($($_.Exception.Message))" "Yellow"
        return
    }

    Write-Log "  TCP-Verbindungen geschlossen: $closed (Anthropic erhalten: $kept)" "Green"
}

# Hyper-V-Firewall: Default Outbound zurueck auf Allow, Allow-Rules entfernt durch Remove-LockdownRules.
function Restore-HyperVTraffic {
    if (-not (Test-HyperVFirewallSupport)) { return }

    $vmCreatorIds = Get-ActiveVMCreatorIds
    foreach ($vmId in $vmCreatorIds) {
        try {
            Set-NetFirewallHyperVVMSetting -Name $vmId `
                -DefaultOutboundAction Allow `
                -DefaultInboundAction Block `
                -ErrorAction Stop
        }
        catch {
            # Manche VM-Creator-Settings sind read-only oder verschwunden
        }
    }
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

    Write-Log "=== NETWORK LOCKDOWN — AKTIVIERUNG ===" "Magenta"
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
    # Schritt 1: Blockiere alles via Profil-Standardaktion
    # (Explizite Block-Regeln wuerden Allow-Regeln uebersteuern!)
    # ──────────────────────────────────────────────

    # Alle bestehenden ausgehenden Allow-Regeln deaktivieren
    Get-NetFirewallRule -Direction Outbound -Action Allow -Enabled True -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -notlike "$RULE_PREFIX*" } |
        Disable-NetFirewallRule -ErrorAction SilentlyContinue

    # Profil-Standardaktionen auf Block setzen
    Set-NetFirewallProfile -All -DefaultOutboundAction Block -DefaultInboundAction Block

    # ──────────────────────────────────────────────
    # Schritt 2: Loopback erlauben
    # ──────────────────────────────────────────────

    New-NetFirewallRule `
        -DisplayName "$RULE_PREFIX - Allow Loopback Out" `
        -Direction Outbound -Action Allow `
        -RemoteAddress 127.0.0.0/8 `
        -Enabled True | Out-Null

    New-NetFirewallRule `
        -DisplayName "$RULE_PREFIX - Allow Loopback In" `
        -Direction Inbound -Action Allow `
        -RemoteAddress 127.0.0.0/8 `
        -Enabled True | Out-Null

    # ──────────────────────────────────────────────
    # Schritt 3: DNS erlauben
    # ──────────────────────────────────────────────

    $dnsIPv4 = @($dnsServers | Where-Object { $_ -notmatch ":" } |
        ForEach-Object { if ($_ -notmatch "/") { "$_/32" } else { $_ } })
    # Filter out loopback (::1), site-local (fec0::), and link-local (fe80::) — WFP rejects these
    $dnsIPv6 = @($dnsServers | Where-Object { $_ -match ":" -and $_ -notmatch "^(::1|fec0:|fe80:)" } |
        ForEach-Object { if ($_ -notmatch "/") { "$_/128" } else { $_ } })

    if ($dnsIPv4.Count -gt 0) {
        New-NetFirewallRule `
            -DisplayName "$RULE_PREFIX - Allow DNS UDP v4" `
            -Direction Outbound -Action Allow `
            -Protocol UDP -RemotePort 53 `
            -RemoteAddress $dnsIPv4 `
            -Enabled True | Out-Null

        New-NetFirewallRule `
            -DisplayName "$RULE_PREFIX - Allow DNS TCP v4" `
            -Direction Outbound -Action Allow `
            -Protocol TCP -RemotePort 53 `
            -RemoteAddress $dnsIPv4 `
            -Enabled True | Out-Null
    }

    if ($dnsIPv6.Count -gt 0) {
        New-NetFirewallRule `
            -DisplayName "$RULE_PREFIX - Allow DNS UDP v6" `
            -Direction Outbound -Action Allow `
            -Protocol UDP -RemotePort 53 `
            -RemoteAddress $dnsIPv6 `
            -Enabled True | Out-Null

        New-NetFirewallRule `
            -DisplayName "$RULE_PREFIX - Allow DNS TCP v6" `
            -Direction Outbound -Action Allow `
            -Protocol TCP -RemotePort 53 `
            -RemoteAddress $dnsIPv6 `
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
            -RemoteAddress $ips.IPv4 `
            -Enabled True | Out-Null

        # Eingehende Antworten fuer etablierte Verbindungen
        New-NetFirewallRule `
            -DisplayName "$RULE_PREFIX - Allow Anthropic Response v4" `
            -Direction Inbound -Action Allow `
            -Protocol TCP -LocalPort 1024-65535 `
            -RemoteAddress $ips.IPv4 `
            -Enabled True | Out-Null
    }

    if ($ips.IPv6.Count -gt 0) {
        New-NetFirewallRule `
            -DisplayName "$RULE_PREFIX - Allow Anthropic HTTPS v6" `
            -Direction Outbound -Action Allow `
            -Protocol TCP -RemotePort 443 `
            -RemoteAddress $ips.IPv6 `
            -Enabled True | Out-Null

        New-NetFirewallRule `
            -DisplayName "$RULE_PREFIX - Allow Anthropic Response v6" `
            -Direction Inbound -Action Allow `
            -Protocol TCP -LocalPort 1024-65535 `
            -RemoteAddress $ips.IPv6 `
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
            -RemoteAddress $dnsIPv4 `
            -Enabled True | Out-Null
    }

    if ($dnsIPv6.Count -gt 0) {
        New-NetFirewallRule `
            -DisplayName "$RULE_PREFIX - Allow DNS Response v6" `
            -Direction Inbound -Action Allow `
            -Protocol UDP -LocalPort 1024-65535 `
            -RemoteAddress $dnsIPv6 `
            -Enabled True | Out-Null
    }

    # ──────────────────────────────────────────────
    # Schritt 6: Hyper-V-Firewall (WSL2 / Docker Desktop)
    # Ohne diese Regeln umgehen Container und WSL2 die Host-Firewall komplett.
    # ──────────────────────────────────────────────
    Block-HyperVTraffic -AllowIPv4 $ips.IPv4 -AllowIPv6 $ips.IPv6 `
        -DnsIPv4 $dnsIPv4 -DnsIPv6 $dnsIPv6

    # ──────────────────────────────────────────────
    # Schritt 7: Strict-Modus — bestehende Verbindungen schliessen
    # ──────────────────────────────────────────────
    if ($Strict) {
        Write-Log "Strict-Modus: schliesse bestehende TCP-Verbindungen..." "Magenta"
        Close-NonAllowedConnections -AllowedIPv4 $ips.IPv4
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
    Write-Log "Forensische Analyse-Guideline:" "Magenta"
    Write-Log "  https://github.com/pepperonas/network-lockdown/blob/main/INCIDENT-RESPONSE-GUIDE.md" "Cyan"
}

function Disable-Lockdown {
    if (-not (Test-Administrator)) {
        Write-Log "Dieses Script benoetigt Administrator-Rechte." "Red"
        return
    }

    Write-Log "=== NETWORK LOCKDOWN — DEAKTIVIERUNG ===" "Magenta"
    Write-Log ""

    # Lockdown-Regeln entfernen (Host + Hyper-V)
    Remove-LockdownRules
    Write-Log "Lockdown-Regeln entfernt" "Cyan"

    # Profil-Standardaktionen wiederherstellen (Allow ist der Windows-Standard)
    Set-NetFirewallProfile -All -DefaultOutboundAction Allow -DefaultInboundAction Block
    Write-Log "Profil-Standardaktionen wiederhergestellt" "Cyan"

    # Hyper-V-VM-Defaults zurueck auf Allow
    Restore-HyperVTraffic
    Write-Log "Hyper-V-VM-Defaults wiederhergestellt" "Cyan"

    # Backup wiederherstellen (stellt auch deaktivierte Regeln wieder her)
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
        # Alle deaktivierten Regeln wieder aktivieren
        Get-NetFirewallRule -Enabled False -ErrorAction SilentlyContinue |
            Enable-NetFirewallRule -ErrorAction SilentlyContinue
        Write-Log "Kein Backup gefunden. Deaktivierte Regeln wieder aktiviert." "Yellow"
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

    if (Test-HyperVFirewallSupport) {
        $hvRules = Get-NetFirewallHyperVRule -DisplayName "$RULE_PREFIX*" -ErrorAction SilentlyContinue
        if ($hvRules) {
            Write-Host ""
            Write-Host "Hyper-V-Firewall-Regeln (WSL2 / Docker):" -ForegroundColor Cyan
            $hvRules | Format-Table DisplayName, Direction, Action, Enabled -AutoSize
        }
    }

    if (Test-DockerOrWSL) {
        Write-Host ""
        if (Test-HyperVFirewallSupport) {
            Write-Host "Docker/WSL2 erkannt: Hyper-V-Firewall filtert Container-/VM-Traffic." -ForegroundColor Yellow
        }
        else {
            Write-Host "Docker/WSL2 erkannt: KEINE Hyper-V-Firewall verfuegbar!" -ForegroundColor Red
            Write-Host "  Container/WSL2 umgehen die Lockdown-Regeln. Empfohlen: 'wsl --shutdown' + Docker beenden." -ForegroundColor Red
        }

        $wslMode = Get-WSLNetworkingMode
        Write-Host "  WSL Networking Mode: $wslMode" -ForegroundColor DarkGray
        if ($wslMode -eq "mirrored") {
            Write-Host "  Hinweis: Mirrored Mode teilt sich den Host-Stack — Host-Firewall greift teilweise direkt." -ForegroundColor DarkGray
            Write-Host "          Hyper-V-Regeln verhalten sich anders als im NAT-Mode." -ForegroundColor DarkGray
        }
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

    # Strict-Modus beim Refresh deaktivieren — wuerde die laufende
    # Anthropic-Verbindung killen.
    $script:Strict = $false

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

    if (Test-HyperVFirewallSupport) {
        $hvRules = Get-NetFirewallHyperVRule -DisplayName "$RULE_PREFIX*" -ErrorAction SilentlyContinue
        if ($hvRules) {
            Write-Host ""
            Write-Host "Hyper-V-Firewall-Regeln (WSL2/Docker):" -ForegroundColor Cyan
            Write-Host ""
            foreach ($rule in $hvRules) {
                Write-Host "[$($rule.Direction)] $($rule.DisplayName)" -ForegroundColor White
                Write-Host "  VMCreator: $($rule.VMCreatorId)" -ForegroundColor DarkGray
                Write-Host "  Action: $($rule.Action) | Enabled: $($rule.Enabled)" -ForegroundColor DarkGray
                if ($rule.RemoteAddresses -and $rule.RemoteAddresses -ne "Any") {
                    Write-Host "  Remote: $($rule.RemoteAddresses -join ', ')" -ForegroundColor DarkGray
                }
                if ($rule.RemotePorts -and $rule.RemotePorts -ne "Any") {
                    Write-Host "  Port: $($rule.Protocol)/$($rule.RemotePorts)" -ForegroundColor DarkGray
                }
                Write-Host ""
            }
        }
    }
}

function Get-Guide {
    $dest = if ($args.Count -gt 0) { $args[0] } else { "." }
    Write-Log "Lade Incident-Response-Guide herunter..." "Cyan"

    try {
        Invoke-WebRequest -Uri "$GITHUB_RAW/INCIDENT-RESPONSE-GUIDE.pdf" `
            -OutFile "$dest\INCIDENT-RESPONSE-GUIDE.pdf" -UseBasicParsing
        Invoke-WebRequest -Uri "$GITHUB_RAW/INCIDENT-RESPONSE-GUIDE.en.pdf" `
            -OutFile "$dest\INCIDENT-RESPONSE-GUIDE.en.pdf" -UseBasicParsing

        Write-Log "Heruntergeladen:" "Green"
        Write-Log "  $dest\INCIDENT-RESPONSE-GUIDE.pdf (Deutsch)" "White"
        Write-Log "  $dest\INCIDENT-RESPONSE-GUIDE.en.pdf (English)" "White"
    }
    catch {
        Write-Log "Download fehlgeschlagen. Pruefe deine Internetverbindung." "Red"
    }
}

function Show-Banner {
    $ver = "v$VERSION"
    $titleText = "NETWORK LOCKDOWN"
    $innerWidth = 58
    $titlePad = $innerWidth - 3 - $titleText.Length - $ver.Length - 3

    Write-Host ""
    Write-Host ("╔" + ("═" * $innerWidth) + "╗") -ForegroundColor Magenta
    Write-Host ("║" + (" " * $innerWidth) + "║") -ForegroundColor Magenta
    # Title
    Write-Host "║" -ForegroundColor Magenta -NoNewline
    Write-Host "   " -NoNewline
    Write-Host $titleText -ForegroundColor White -NoNewline
    Write-Host (" " * $titlePad) -NoNewline
    Write-Host $ver -ForegroundColor DarkGray -NoNewline
    Write-Host "   " -NoNewline
    Write-Host "║" -ForegroundColor Magenta
    # Separator
    Write-Host "║" -ForegroundColor Magenta -NoNewline
    Write-Host ("   " + ("━" * 52) + "   ") -ForegroundColor DarkGray -NoNewline
    Write-Host "║" -ForegroundColor Magenta
    # Description
    Write-Host "║" -ForegroundColor Magenta -NoNewline
    Write-Host ("   Kernel-level emergency network isolation" + (" " * 15)) -NoNewline
    Write-Host "║" -ForegroundColor Magenta
    # Platform
    Write-Host "║" -ForegroundColor Magenta -NoNewline
    Write-Host "   Platform: " -NoNewline
    Write-Host "Windows" -ForegroundColor Green -NoNewline
    Write-Host " " -NoNewline
    Write-Host "(WFP/NetSecurity)" -ForegroundColor DarkGray -NoNewline
    Write-Host (" " * 20) -NoNewline
    Write-Host "║" -ForegroundColor Magenta
    # Empty
    Write-Host ("║" + (" " * $innerWidth) + "║") -ForegroundColor Magenta
    # Developer
    Write-Host "║" -ForegroundColor Magenta -NoNewline
    Write-Host "   " -NoNewline
    Write-Host "Martin Pfeffer - celox.io" -ForegroundColor DarkGray -NoNewline
    Write-Host (" " * 30) -NoNewline
    Write-Host "║" -ForegroundColor Magenta
    # Empty
    Write-Host ("║" + (" " * $innerWidth) + "║") -ForegroundColor Magenta
    # Bottom
    Write-Host ("╚" + ("═" * $innerWidth) + "╝") -ForegroundColor Magenta
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
    Write-Host "  guide    Incident-Response-Guide (PDF) herunterladen"
    Write-Host "  help     Diese Hilfe anzeigen"
    Write-Host ""
    Write-Host "Optionen:"
    Write-Host "  -Strict, -s   Bestehende TCP-Verbindungen schliessen via SetTcpEntry"
    Write-Host "                (killt laufende Sessions zu nicht-Anthropic-IPs)"
    Write-Host ""
    Write-Host "Hinweis: Erfordert Administrator-Rechte (Als Admin ausfuehren)." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Forensische Analyse-Guideline:" -ForegroundColor Magenta
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
    "guide"   { Get-Guide }
    "help"    { Show-Help }
    default   { Show-Help }
}
