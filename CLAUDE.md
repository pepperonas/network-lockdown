# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Emergency network lockdown scripts for macOS, Linux, and Windows. Blocks all network traffic at kernel level except Claude Code CLI connections to the Anthropic API. Used for AI-assisted incident response on compromised machines.

## Linting and Testing

CI runs on GitHub Actions (`.github/workflows/ci.yml`) with 4 jobs: lint, test-linux, test-macos, test-windows. All test jobs depend on lint passing first.

**Lint locally:**
```bash
# Bash syntax
bash -n network-lockdown-linux.sh && bash -n network-lockdown-mac.sh

# ShellCheck (excludes: SC2086 SC1091 SC2155 SC2120)
shellcheck --severity=warning --exclude=SC2086,SC1091,SC2155,SC2120 network-lockdown-linux.sh network-lockdown-mac.sh

# PowerShell syntax (requires pwsh)
pwsh -c '[System.Management.Automation.Language.Parser]::ParseFile("network-lockdown-windows.ps1", [ref]$null, [ref]$errors) | Out-Null; if ($errors.Count -gt 0) { $errors; exit 1 }'
```

**Integration tests require root/admin** and actually modify firewall rules. The CI tests activate lockdown, verify Anthropic API is reachable while Google is blocked, then deactivate and verify restoration. Every test job has an `if: always()` cleanup step.

## Architecture

All three scripts share the same structure and command interface (`on`, `off`, `status`, `refresh`, `rules`, `guide`, `help`), but use platform-specific firewall APIs:

| | macOS | Linux | Windows |
|---|---|---|---|
| Script | `network-lockdown-mac.sh` | `network-lockdown-linux.sh` | `network-lockdown-windows.ps1` |
| Firewall | PF (`pfctl`) | Netfilter (`iptables`/`ip6tables`) | WFP (`New-NetFirewallRule`) |
| Lockfile | `/tmp/claude-lockdown.active` | `/tmp/claude-lockdown.active` | `$env:TEMP\claude-lockdown.active` |
| DNS tool | `dig` | `dig` | `Resolve-DnsName` |

**Shared function structure** (same in all scripts):
- `resolve_ips` / `Resolve-AnthropicIPs` — resolves `api.anthropic.com`, `statsig.anthropic.com`, `api.statsig.com` to IPv4/IPv6
- `activate_lockdown` / `Enable-Lockdown` — backs up firewall, creates block+allow rules, writes lockfile
- `deactivate_lockdown` / `Disable-Lockdown` — removes rules, restores backup, deletes lockfile
- `show_status` / `Show-Status` — displays lockdown state and connectivity test
- `refresh_ips` / `Update-IPs` — re-resolves IPs and recreates rules without full deactivation
- `download_guide` / `Download-Guide` — fetches the Incident Response PDF from GitHub (`pepperonas/network-lock`)

**Allowed traffic when locked down:**
- Anthropic API IPs on TCP port 443 (resolved at activation time)
- DNS (port 53 UDP/TCP) to system DNS servers
- Loopback (127.0.0.0/8)
- Established/related connections (conntrack on Linux, `flags A/A` on macOS)

## Windows-Specific Gotchas

These are hard-won lessons from CI debugging:

- **Block vs Allow precedence**: Windows Firewall evaluates Block rules before Allow rules. Explicit "Block All" rules override "Allow" rules. Use `Set-NetFirewallProfile -DefaultOutboundAction Block` instead.
- **WFP rejects certain IPv6 addresses**: `::1`, `fec0::*`, `fe80::*` cannot be used as `-RemoteAddress` in `New-NetFirewallRule`. Filter these out.
- **IPs ending in .0**: WFP rejects addresses like `34.128.128.0` without a CIDR suffix. Always append `/32` (IPv4) or `/128` (IPv6).
- **Array parameters**: Pass arrays directly to `-RemoteAddress` (not `-join ","`). The cmdlet expects `String[]`, not a comma-separated string.
- **PowerShell streams**: `Write-Host` outputs to stream 6 (Information), not stdout. Use `*>&1` to capture all streams.
- **`$ErrorActionPreference = "Stop"`**: Any error terminates the script. Wrap external commands like `netsh` in try/catch.

## Docker / Container-Bypass-Schutz

Docker (und WSL2) können den Lockdown ohne Gegenmaßnahmen umgehen:
- **Linux**: Ein laufender Docker-Daemon kann iptables-Regeln neu erzeugen und über den FORWARD-Chain Container-Traffic an der DROP-Policy vorbeischleusen ([UFW-Docker-Bypass](https://zeonedge.com/blog/ufw-docker-firewall-bypass-fix)).
- **Windows**: WSL2 und Docker Desktop laufen in Hyper-V-VMs und umgehen `New-NetFirewallRule` komplett ([Hyper-V Firewall](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/hyper-v-firewall)).
- **macOS**: Geringes Risiko — `com.docker.backend` ist normaler Host-Prozess, PF greift.

Was die Skripte dagegen tun:

| | Maßnahme |
|---|---|
| **Linux** (`block_container_traffic`) | Erkennt Docker, Podman, LXC/LXD, containerd, libvirt, K8s/CNI (auch Bridges wie `podman*`, `cni*`, `lxcbr*`, `virbr*`, `flannel*`, `cilium*`). DROP in `DOCKER-USER`/`CNI-FORWARD`/`KUBE-FORWARD`/`LIBVIRT_FWO` (vor Daemon-Regeln) + DROP in FORWARD für alle erkannten Bridges/veth/tun-Interfaces (IPv4+IPv6). Heuristik via `list_container_bridges`: alles außer Loopback und Default-Route-Interface. |
| **Windows** (`Block-HyperVTraffic`) | Iteriert über alle aktiven VMCreatorIds via `Get-NetFirewallHyperVVMSetting -PolicyStore ActiveStore`. Setzt `DefaultOutboundAction = Block` und legt `New-NetFirewallHyperVRule` Allow-Regeln für Anthropic + DNS + Loopback an. Erfordert Win 11 22H2+. WSL-Mirrored-Mode wird via `Get-WSLNetworkingMode` erkannt und gewarnt. |
| **macOS** (`detect_docker`) | Detection + Warning. PF filtert Container-Traffic bereits auf Paket-Ebene; keine Regelmodifikation nötig. |

**Weitere Vorkehrungen:**
- **Race-Fix**: Default-Policy `DROP` wird **vor** dem Flush gesetzt (Linux), macOS nutzt atomares `pfctl -f` ohne separaten Flush. Verhindert das offene Fenster zwischen Regel-Flush und neuer Policy.
- **nftables-Awareness** (Linux, `check_nftables`): Warnt, wenn native nft-Tabellen existieren, die nicht via iptables verwaltet werden (firewalld, eBPF/Cilium). Diese werden nicht im Backup erfasst.
- **socketfilterfw** (macOS, `check_app_firewall`): Warnt, wenn macOS Application Firewall im Block-All-Modus läuft — kann Anthropic-Traffic unabhängig vom Lockdown blocken.
- **`--strict` Flag** (alle Plattformen): killt bestehende Verbindungen statt nur neue zu blocken.
  - Linux: `conntrack -F` + `ss --kill state established`
  - macOS: `pfctl -F states`
  - Windows: `iphlpapi.dll!SetTcpEntry` mit `MIB_TCP_STATE_DELETE_TCB` (TCPView-Methode, killt Verbindungen ohne Prozesse zu killen)
  - Wird beim `refresh` automatisch deaktiviert, um die laufende Anthropic-Session nicht zu killen.

**Cleanup**:
- Linux: `iptables-restore` aus Backup räumt unsere DROP-Regeln mit ab. Falls Container-Netzwerke nach Lockdown nicht arbeiten, hilft `systemctl restart docker` (bzw. podman/containerd/libvirtd).
- Windows: `Restore-HyperVTraffic` setzt `DefaultOutboundAction = Allow` zurück, `Remove-LockdownRules` löscht auch HyperV-Rules.

## Documentation

- `README.md` / `README.en.md` — German/English project README
- `INCIDENT-RESPONSE-GUIDE.md` / `INCIDENT-RESPONSE-GUIDE.en.md` — 11-phase incident response guide with Claude Code prompts
- All German docs use proper UTF-8 umlauts (ü, ö, ä, ß), not ASCII substitutions
