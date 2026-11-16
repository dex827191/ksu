# SSH Protocol KSU

Standalone KernelSU module based on the two supplied archives:
- `SSH Protocol.zip` (Kotlin SSH/SOCKS5 tunnel implementation)
- `hev-socks5-tunnel-main.zip` (HEV tun2socks C engine)

## Current implementation

### Go engine
- SSH password and private-key authentication (Go `x/crypto/ssh`)
- Strict known-host verification using OpenSSH `known_hosts`; host-key scan command prints the fingerprint and line for review
- The six source-app connection modes: `ssh_only`, `ssh_proxy`, `ssh_sni`, `ssh_proxy_payload`, `ssh_payload_sni`, `ssh_proxy_payload_sni`
- HTTP CONNECT proxy, optional Basic proxy authentication
- TLS SNI with configurable TLS 1.0/1.1/1.2/1.3 selection (legacy versions are not recommended)
- Normal payload placeholders matching the supplied `PayloadPlaceholderResolver`
- Enhanced payload `[split]`, `[splitnodelay]`, `[instant_split]`, `[delay]`, `[delay_split]`, `[split_delay]` with 1 second delay semantics
- Local SOCKS5 TCP CONNECT server compatible with the original app's `Socks5Server`
- SSH keepalive and reconnect loop with exponential backoff

### KernelSU module
- `action.sh start|stop|restart|status|stats|logs|route-on|route-off`
- KernelSU WebUI to edit profiles, choose modes, scan/add host keys, start/stop/restart, inspect logs and TUN byte counters
- Optional boot auto-start
- Optional global routing policy with a separate route table and mark-based upstream bypass
- HEV tun2socks binary built for Android ARM64 and ARMv7 by GitHub Actions

## Build

Push this repository to GitHub, then run **Actions → Build SSH Protocol KSU**. The workflow builds:
- `SSHProtocol-KSU-arm64.zip`
- `SSHProtocol-KSU-arm.zip`

The build uses Android NDK for HEV and Go for the SSH engine. Install the matching ZIP in KernelSU.

## First connection
1. Install and reboot (or use KernelSU's hot-install if supported by the device).
2. Open the module WebUI.
3. Fill SSH host, port, username and password/private key.
4. Press **SCAN SSH HOST KEY**. Verify the displayed SHA256 fingerprint against your SSH server/provider using a trusted channel.
5. Save the generated known_hosts line and configuration.
6. Start the tunnel.
7. Test the local SOCKS endpoint `127.0.0.1:10808`.
8. Only after confirming traffic, optionally enable ROUTE ON.

## Important limitations / correctness notes

- The supplied Android app's SOCKS5 server accepts only `CONNECT`; it rejects UDP ASSOCIATE and other SOCKS commands. This Go port deliberately matches that TCP-only behavior. HEV's UDP relay mode requires a SOCKS5 UDP-capable upstream, so UDP applications and UDP DNS are not fully tunneled by this implementation. Do not assume complete UDP coverage.
- The original app uses Android VPNService and app-level service lifecycle. KernelSU cannot use that Android VPNService from a shell module. This module instead creates a Linux TUN with HEV and uses root routing rules. ROM-specific policy routing, netd, IPv6, firewall and DNS behaviour must be tested on the target device.
- Global routing is opt-in. It can disrupt connectivity on some ROMs. `route-off` or `stop` removes this module's policy rules and route table; keep ADB/recovery access available while testing.
- The Go engine is a reimplementation of the app's transport pipeline, not a binary-compatible port of its Kotlin classes. Profile URI import/export, app-specific enhanced parser edge cases, traffic accounting semantics, notification service, wake lock and Android UI are not yet ported.
- The HEV engine itself supports TCP and UDP, but its upstream SOCKS UDP requirements are not met by the original app's TCP-only SOCKS server. Full UDP requires adding a UDP-capable relay protocol and corresponding server support; it cannot be honestly claimed as complete from the supplied source.
- No compiled Android binaries are included in the source ZIP. GitHub Actions must complete successfully before the module ZIP is installable.

## Manual commands

```sh
su -c '/data/adb/modules/sshprotocol_ksu/action.sh start'
su -c '/data/adb/modules/sshprotocol_ksu/action.sh status'
su -c '/data/adb/modules/sshprotocol_ksu/action.sh stats'
su -c '/data/adb/modules/sshprotocol_ksu/action.sh logs'
su -c '/data/adb/modules/sshprotocol_ksu/action.sh route-off'
su -c '/data/adb/modules/sshprotocol_ksu/action.sh stop'
```

## Security
`host_key_policy` defaults to `strict`. Verify fingerprints out-of-band. The `insecure` setting disables SSH server identity verification and should only be used temporarily for isolated testing. Config and known_hosts are stored under `/data/adb/sshprotocol` with restrictive permissions.
