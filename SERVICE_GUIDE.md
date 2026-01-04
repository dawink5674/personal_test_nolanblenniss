# Liaison Service Guide

Post-installation usage guide for all services deployed by the MWCCDC Liaison Ansible playbook.

---

## Table of Contents
- [VPN Services](#vpn-services)
  - [WireGuard](#wireguard)
  - [OpenVPN](#openvpn)
  - [SoftEther](#softether)
- [Docker](#docker)
- [Network Scanning](#network-scanning)
  - [Subnet Ping](#subnet-ping)
  - [Nmap Scanner](#nmap-scanner)
  - [TShark Tools](#tshark-tools)
- [Security Tools](#security-tools)
  - [FIM Monitor](#fim-monitor)
  - [Honeypot (Endlessh)](#honeypot-endlessh)
  - [IDS (Suricata)](#ids-suricata)
- [System Tools](#system-tools)
  - [NTP (Chrony)](#ntp-chrony)
  - [PowerShell](#powershell)
  - [System Enumeration](#system-enumeration)

---

## VPN Services

### WireGuard

**Installation:**
```bash
ansible-playbook playbooks/liaison_main.yml -e tool=vpn -e vpn_type=wireguard
```

**View Server Keys:**
```bash
# View server public key (share with clients)
sudo cat /etc/wireguard/server_public.key

# View server private key (keep secret)
sudo cat /etc/wireguard/server_private.key
```

**View Client Keys:**
```bash
# View client public key
sudo cat /etc/wireguard/client_public.key

# View client private key (for client config)
sudo cat /etc/wireguard/client_private.key
```

**Manage WireGuard Service:**
```bash
# Start WireGuard
sudo systemctl start wg-quick@wg0

# Stop WireGuard
sudo systemctl stop wg-quick@wg0

# Restart WireGuard
sudo systemctl restart wg-quick@wg0

# Check status
sudo systemctl status wg-quick@wg0

# Enable on boot
sudo systemctl enable wg-quick@wg0
```

**WireGuard Commands:**
```bash
# Show interface status and connected peers
sudo wg show

# Show detailed stats
sudo wg show wg0

# Bring interface up manually
sudo wg-quick up wg0

# Bring interface down
sudo wg-quick down wg0
```

**View/Edit Configuration:**
```bash
# View server config
sudo cat /etc/wireguard/wg0.conf

# Edit config (restart after changes)
sudo nano /etc/wireguard/wg0.conf
```

**Client Configuration Template:**
Create this on your client device:
```ini
[Interface]
PrivateKey = <client_private_key>
Address = 10.0.0.2/24
DNS = 1.1.1.1

[Peer]
PublicKey = <server_public_key>
Endpoint = <server_ip>:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
```

**Add a New Peer (Client):**
```bash
# Generate new client keys
wg genkey | tee client2_private.key | wg pubkey > client2_public.key

# Add peer to server config
sudo wg set wg0 peer $(cat client2_public.key) allowed-ips 10.0.0.3/32
```

---

### OpenVPN

**Installation:**
```bash
ansible-playbook playbooks/liaison_main.yml -e tool=vpn -e vpn_type=openvpn
```

**View PKI Certificates:**
```bash
# Server certificate
sudo cat /etc/openvpn/easy-rsa/pki/issued/server.crt

# CA certificate (needed by clients)
sudo cat /etc/openvpn/ca.crt

# List all issued certificates
ls -la /etc/openvpn/easy-rsa/pki/issued/
```

**Manage OpenVPN Service:**
```bash
# Start OpenVPN server
sudo systemctl start openvpn@server

# Stop OpenVPN server
sudo systemctl stop openvpn@server

# Restart OpenVPN
sudo systemctl restart openvpn@server

# Check status
sudo systemctl status openvpn@server

# View logs
sudo journalctl -u openvpn@server -f
```

**Generate Client Certificate:**
```bash
cd /etc/openvpn/easy-rsa
sudo ./easyrsa gen-req client1 nopass
sudo ./easyrsa sign-req client client1
```

**View Server Configuration:**
```bash
sudo cat /etc/openvpn/server.conf
```

**Client Configuration Template:**
```ini
client
dev tun
proto udp
remote <server_ip> 1194
resolv-retry infinite
nobind
persist-key
persist-tun
ca ca.crt
cert client.crt
key client.key
remote-cert-tls server
cipher AES-256-GCM
verb 3
```

**Check Connected Clients:**
```bash
# View status log
sudo cat /var/log/openvpn/status.log

# Or if using management interface
echo "status" | nc localhost 7505
```

---

### SoftEther

**Installation:**
```bash
ansible-playbook playbooks/liaison_main.yml -e tool=vpn -e vpn_type=softether -e softether_server_password=YourPassword
```

**Manage SoftEther Service:**
```bash
# Start SoftEther
sudo systemctl start vpnserver

# Stop SoftEther
sudo systemctl stop vpnserver

# Restart SoftEther
sudo systemctl restart vpnserver

# Check status
sudo systemctl status vpnserver
```

**SoftEther Command Line (vpncmd):**
```bash
# Enter server management mode
sudo /opt/vpnserver/vpncmd localhost /SERVER /PASSWORD:YourPassword

# Common commands inside vpncmd:
# List virtual hubs
HubList

# Create new hub
HubCreate MyHub

# Set hub password
HubSetPassword MyHub

# Create user
UserCreate username

# Set user password
UserPasswordSet username

# List users
UserList

# View server status
ServerStatusGet

# Exit vpncmd
exit
```

**Quick Setup Commands:**
```bash
# One-liner to check server status
echo "ServerStatusGet" | sudo /opt/vpnserver/vpncmd localhost /SERVER /PASSWORD:YourPassword /CMD

# List all hubs
echo "HubList" | sudo /opt/vpnserver/vpncmd localhost /SERVER /PASSWORD:YourPassword /CMD
```

**View Logs:**
```bash
# Server logs
sudo tail -f /opt/vpnserver/server_log/*.log

# Security logs
sudo tail -f /opt/vpnserver/security_log/*.log
```

**Ports Used:**
- 443 (HTTPS/SSL-VPN)
- 992 (SSL-VPN alternate)
- 1194 (OpenVPN compatible)
- 5555 (SoftEther default)

---

## Docker

**Installation:**
```bash
ansible-playbook playbooks/liaison_main.yml -e tool=docker
```

**Basic Docker Commands:**
```bash
# Check Docker is running
sudo systemctl status docker

# View running containers
docker ps

# View all containers (including stopped)
docker ps -a

# View images
docker images

# Pull an image
docker pull nginx:latest

# Run a container
docker run -d --name mycontainer -p 8080:80 nginx

# Stop a container
docker stop mycontainer

# Start a container
docker start mycontainer

# Remove a container
docker rm mycontainer

# Remove an image
docker rmi nginx:latest
```

**Docker Compose:**
```bash
# Start services defined in docker-compose.yml
docker compose up -d

# Stop services
docker compose down

# View logs
docker compose logs -f

# Rebuild and start
docker compose up -d --build
```

**Container Management:**
```bash
# Execute command in running container
docker exec -it mycontainer /bin/bash

# View container logs
docker logs mycontainer
docker logs -f mycontainer  # Follow logs

# Inspect container
docker inspect mycontainer

# View container resource usage
docker stats
```

**Cleanup Commands:**
```bash
# Remove all stopped containers
docker container prune

# Remove unused images
docker image prune

# Remove all unused data (containers, networks, images)
docker system prune -a

# View disk usage
docker system df
```

---

## Network Scanning

### Subnet Ping

**Installation:**
```bash
ansible-playbook playbooks/liaison_main.yml -e tool=subnet -e subnet_cidr=192.168.1.0/24
```

**Manual Subnet Scanning:**
```bash
# Basic ping sweep
nmap -sn 192.168.1.0/24

# Ping sweep with hostnames
nmap -sn -R 192.168.1.0/24

# Fast ping sweep (no DNS resolution)
nmap -sn -n 192.168.1.0/24

# Save results to file
nmap -sn 192.168.1.0/24 -oN scan_results.txt

# Output in all formats
nmap -sn 192.168.1.0/24 -oA subnet_scan
```

**View Scan Results:**
```bash
# Results are saved to liaison log directory
cat /var/log/liaison/subnet-scan-*.nmap
```

---

### Nmap Scanner

**Installation:**
```bash
ansible-playbook playbooks/liaison_main.yml -e tool=nmap -e nmap_type=aggressive -e nmap_target=10.0.0.1
```

**Scan Types Available:**
```bash
# Ping scan (host discovery)
nmap -sn 10.0.0.1

# Port scan (all ports)
nmap -p- -T4 10.0.0.1

# Service version detection
nmap -sV 10.0.0.1

# OS detection
nmap -O 10.0.0.1

# Vulnerability scan
nmap --script vuln 10.0.0.1

# Aggressive scan (OS, version, scripts, traceroute)
nmap -A 10.0.0.1
```

**Common Nmap Commands:**
```bash
# Quick scan of common ports
nmap -F 10.0.0.1

# Scan specific ports
nmap -p 22,80,443 10.0.0.1

# Scan port range
nmap -p 1-1000 10.0.0.1

# UDP scan
sudo nmap -sU 10.0.0.1

# Stealth SYN scan
sudo nmap -sS 10.0.0.1

# Script scan (default scripts)
nmap -sC 10.0.0.1

# Save results
nmap -A 10.0.0.1 -oA /var/log/liaison/nmap_logs/full_scan
```

**View Results:**
```bash
# Nmap results location
ls -la /var/log/liaison/nmap_logs/

# View latest scan
cat /var/log/liaison/nmap_logs/scan-*.nmap
```

---

### TShark Tools

**Installation:**
```bash
ansible-playbook playbooks/liaison_main.yml -e tool=tshark -e tshark_action=capture
```

**Basic TShark Commands:**
```bash
# List available interfaces
tshark -D

# Capture on specific interface
sudo tshark -i eth0

# Capture with packet count limit
sudo tshark -i eth0 -c 100

# Capture and save to file
sudo tshark -i eth0 -w capture.pcap

# Capture with time limit (seconds)
sudo tshark -i eth0 -a duration:60 -w capture.pcap
```

**Capture Filters (BPF syntax):**
```bash
# Capture only TCP traffic
sudo tshark -i eth0 -f "tcp"

# Capture specific port
sudo tshark -i eth0 -f "port 80"

# Capture specific host
sudo tshark -i eth0 -f "host 192.168.1.100"

# Capture HTTP traffic
sudo tshark -i eth0 -f "tcp port 80 or tcp port 443"

# Exclude SSH (useful when remote)
sudo tshark -i eth0 -f "not port 22"
```

**Reading PCAP Files:**
```bash
# Read pcap file
tshark -r capture.pcap

# Read with packet limit
tshark -r capture.pcap -c 50

# Read with display filter
tshark -r capture.pcap -Y "http"

# Extract specific fields
tshark -r capture.pcap -T fields -e ip.src -e ip.dst -e tcp.port
```

**Display Filters:**
```bash
# Filter HTTP requests
tshark -r capture.pcap -Y "http.request"

# Filter by IP
tshark -r capture.pcap -Y "ip.addr == 192.168.1.100"

# Filter DNS queries
tshark -r capture.pcap -Y "dns.qry.name"

# Filter failed connections
tshark -r capture.pcap -Y "tcp.flags.reset == 1"
```

**Analysis Commands:**
```bash
# Protocol hierarchy statistics
tshark -r capture.pcap -q -z io,phs

# Conversation statistics
tshark -r capture.pcap -q -z conv,ip

# HTTP statistics
tshark -r capture.pcap -q -z http,tree

# Follow TCP stream
tshark -r capture.pcap -q -z follow,tcp,ascii,0
```

**View Captured Files:**
```bash
cat /var/log/liaison/capture.pcap  # Binary - use tshark to read
tshark -r /var/log/liaison/capture.pcap
```

---

## Security Tools

### FIM Monitor

**Installation:**
```bash
# Start monitoring
ansible-playbook playbooks/liaison_main.yml -e tool=fim -e fim_choice=1

# List active monitors
ansible-playbook playbooks/liaison_main.yml -e tool=fim -e fim_choice=2

# Stop monitoring
ansible-playbook playbooks/liaison_main.yml -e tool=fim -e fim_choice=3

# View changes
ansible-playbook playbooks/liaison_main.yml -e tool=fim -e fim_choice=4
```

**FIM Choices:**
| Choice | Action |
|--------|--------|
| 1 | Create baseline and start monitoring |
| 2 | List active FIM sessions |
| 3 | Stop and remove a monitor |
| 4 | View detected changes |

**Manual FIM Commands:**
```bash
# View active FIM sessions
ls -la /tmp/fim_sessions/

# View baseline for a session
cat /tmp/fim_sessions/<session_id>/baseline.txt

# View detected changes
cat /tmp/fim_sessions/<session_id>/changes.log

# View FIM cron jobs
crontab -l | grep FIM

# Manually check for changes
find /etc -type f -exec md5sum {} + > /tmp/current.txt
diff /tmp/fim_sessions/<session_id>/baseline.txt /tmp/current.txt
```

**Create Manual Baseline:**
```bash
# Create baseline of /etc directory
find /etc -type f -exec md5sum {} + 2>/dev/null > /tmp/etc_baseline.txt

# Compare later
find /etc -type f -exec md5sum {} + 2>/dev/null > /tmp/etc_current.txt
diff /tmp/etc_baseline.txt /tmp/etc_current.txt
```

---

### Honeypot (Endlessh)

**Installation:**
```bash
ansible-playbook playbooks/liaison_main.yml -e tool=honeypot
```

**Manage Endlessh Service:**
```bash
# Start Endlessh
sudo systemctl start endlessh

# Stop Endlessh
sudo systemctl stop endlessh

# Check status
sudo systemctl status endlessh

# View logs
sudo journalctl -u endlessh -f
```

**View Configuration:**
```bash
# View config
cat /etc/endlessh/config

# Default config options:
# Port 2222          - Port to listen on
# Delay 10000        - Milliseconds between sends
# MaxLineLength 32   - Max banner line length
# MaxClients 4096    - Max concurrent clients
# LogLevel 1         - 0=silent, 1=connections, 2=verbose
```

**Monitor Trapped Connections:**
```bash
# Watch real-time connections
sudo journalctl -u endlessh -f

# Count trapped IPs
sudo journalctl -u endlessh | grep "ACCEPT" | awk '{print $NF}' | sort | uniq -c | sort -rn

# View connection duration
sudo journalctl -u endlessh | grep "CLOSE"
```

**Redirect Real SSH (Optional):**
```bash
# Move real SSH to different port first
sudo sed -i 's/#Port 22/Port 2222/' /etc/ssh/sshd_config
sudo systemctl restart sshd

# Then set Endlessh to port 22
sudo sed -i 's/Port 2222/Port 22/' /etc/endlessh/config
sudo systemctl restart endlessh
```

**Firewall Configuration:**
```bash
# Allow honeypot port
sudo ufw allow 2222/tcp comment "Endlessh honeypot"

# If using port 22 for honeypot
sudo ufw allow 22/tcp comment "Endlessh honeypot"
```

---

### IDS (Suricata)

**Installation:**
```bash
# Install as IDS (passive monitoring)
ansible-playbook playbooks/liaison_main.yml -e tool=ids -e ids_type=IDS

# Install as IPS (inline blocking)
ansible-playbook playbooks/liaison_main.yml -e tool=ids -e ids_type=IPS
```

**Manage Suricata Service:**
```bash
# Start Suricata
sudo systemctl start suricata

# Stop Suricata
sudo systemctl stop suricata

# Restart Suricata
sudo systemctl restart suricata

# Check status
sudo systemctl status suricata

# Test configuration
sudo suricata -T -c /etc/suricata/suricata.yaml
```

**Update Rules:**
```bash
# Update Suricata rules
sudo suricata-update

# Update and restart
sudo suricata-update && sudo systemctl restart suricata

# List enabled rule sources
sudo suricata-update list-sources

# Enable a rule source
sudo suricata-update enable-source et/open
```

**View Logs and Alerts:**
```bash
# View fast.log (alerts)
sudo tail -f /var/log/suricata/fast.log

# View eve.json (detailed JSON logs)
sudo tail -f /var/log/suricata/eve.json

# Parse eve.json for alerts
sudo cat /var/log/suricata/eve.json | jq 'select(.event_type=="alert")'

# View stats
sudo cat /var/log/suricata/stats.log
```

**Common Alert Analysis:**
```bash
# Count alerts by signature
sudo cat /var/log/suricata/eve.json | jq -r 'select(.event_type=="alert") | .alert.signature' | sort | uniq -c | sort -rn

# View alerts from specific IP
sudo cat /var/log/suricata/eve.json | jq 'select(.event_type=="alert" and .src_ip=="192.168.1.100")'

# Get top source IPs
sudo cat /var/log/suricata/eve.json | jq -r 'select(.event_type=="alert") | .src_ip' | sort | uniq -c | sort -rn | head -20
```

**Custom Rules:**
```bash
# View custom rules
cat /etc/suricata/rules/custom.rules

# Add a custom rule
echo 'alert tcp any any -> any 4444 (msg:"Possible Meterpreter"; sid:1000003; rev:1;)' | sudo tee -a /etc/suricata/rules/custom.rules

# Reload rules
sudo suricatasc -c reload-rules
```

**Suricata Socket Commands:**
```bash
# Connect to Suricata socket
sudo suricatasc

# Inside suricatasc:
# Get running mode
>>> running-mode

# Get stats
>>> dump-counters

# Reload rules
>>> reload-rules

# Shutdown
>>> shutdown
```

---

## System Tools

### NTP (Chrony)

**Installation:**
```bash
ansible-playbook playbooks/liaison_main.yml -e tool=ntp
```

**Manage Chrony Service:**
```bash
# Start Chrony
sudo systemctl start chrony

# Stop Chrony
sudo systemctl stop chrony

# Restart Chrony
sudo systemctl restart chrony

# Check status
sudo systemctl status chrony
```

**Chrony Commands:**
```bash
# View time sources
chronyc sources

# View detailed source info
chronyc sources -v

# View tracking (sync status)
chronyc tracking

# View activity
chronyc activity

# Force sync now
sudo chronyc makestep

# View clients (on server)
chronyc clients
```

**Check Time Synchronization:**
```bash
# Quick sync status
chronyc tracking | grep "Leap status"

# Check if synchronized
timedatectl status

# View system time vs NTP
chronyc tracking | grep -E "Reference|System|Last"
```

**Configuration:**
```bash
# View config
cat /etc/chrony/chrony.conf

# Add NTP server manually
echo "server time.google.com iburst" | sudo tee -a /etc/chrony/chrony.conf
sudo systemctl restart chrony
```

**Troubleshooting:**
```bash
# Check if chrony can reach servers
chronyc sourcestats

# Check NTP port
sudo ss -ulnp | grep 123

# Test specific server
chronyd -Q "server pool.ntp.org iburst"
```

---

### PowerShell

**Installation:**
```bash
ansible-playbook playbooks/liaison_main.yml -e tool=powershell -l localhost
```

**Start PowerShell:**
```bash
# Start PowerShell
pwsh

# Run single command
pwsh -Command "Get-Process"

# Run script file
pwsh -File script.ps1
```

**Basic PowerShell Commands:**
```powershell
# Get help
Get-Help Get-Process

# List processes
Get-Process

# List services
Get-Service

# Get system info
Get-ComputerInfo

# List files
Get-ChildItem /home

# Read file content
Get-Content /etc/passwd

# Find files
Get-ChildItem -Recurse -Filter "*.log"
```

**PowerShell for Linux Administration:**
```powershell
# Get network info
Get-NetIPAddress

# Get disk usage
Get-PSDrive

# Check service status
Get-Service ssh

# Run bash commands
bash -c "df -h"

# Get environment variables
Get-ChildItem Env:
```

**PowerShell Remoting (PSRemoting):**
```powershell
# Enable remoting (requires setup)
Enable-PSRemoting -Force

# Connect to remote Linux
Enter-PSSession -HostName 192.168.1.100 -UserName admin

# Run remote command
Invoke-Command -HostName 192.168.1.100 -UserName admin -ScriptBlock { Get-Process }
```

**Useful Scripts:**
```powershell
# List listening ports
Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort, OwningProcess

# Find large files
Get-ChildItem -Recurse | Where-Object {$_.Length -gt 100MB}

# Monitor log file
Get-Content /var/log/syslog -Tail 10 -Wait
```

**Check PowerShell Version:**
```powershell
$PSVersionTable
```

---

### System Enumeration

**Installation:**
```bash
ansible-playbook playbooks/liaison_main.yml -e tool=system
```

**View Enumeration Reports:**
```bash
# Reports are saved to liaison log directory
ls -la /var/log/liaison/enum/

# View latest report
cat /var/log/liaison/enum/report-*.txt
```

**Manual Enumeration Commands:**
```bash
# Listening ports
ss -tulnp

# All connections
ss -anp

# Running processes (sorted by memory)
ps aux --sort=-%mem

# Running processes (sorted by CPU)
ps aux --sort=-%cpu

# Last logins
last -n 20

# Failed login attempts
lastb -n 20

# Current logged in users
who
w

# User accounts
cat /etc/passwd

# Scheduled tasks (cron)
crontab -l
sudo ls -la /etc/cron.d/
sudo cat /etc/crontab

# Systemd timers
systemctl list-timers

# Installed packages (Debian/Ubuntu)
dpkg -l

# Installed packages (RHEL/CentOS)
rpm -qa

# Open files
lsof -i

# Network interfaces
ip addr
ip route

# Firewall rules
sudo iptables -L -n -v
sudo ufw status verbose

# System info
uname -a
hostnamectl
cat /etc/os-release

# Disk usage
df -h
du -sh /*

# Memory usage
free -h

# Uptime and load
uptime
```

**Security Enumeration:**
```bash
# SUID binaries
find / -perm -4000 -type f 2>/dev/null

# World-writable files
find / -perm -002 -type f 2>/dev/null

# Files modified in last 24h
find / -mtime -1 -type f 2>/dev/null

# SSH authorized keys
cat ~/.ssh/authorized_keys
find /home -name "authorized_keys" 2>/dev/null

# Sudo permissions
sudo -l
cat /etc/sudoers
```

---

## Quick Reference

### Service Management (systemctl)
```bash
sudo systemctl start <service>
sudo systemctl stop <service>
sudo systemctl restart <service>
sudo systemctl status <service>
sudo systemctl enable <service>   # Start on boot
sudo systemctl disable <service>  # Don't start on boot
sudo journalctl -u <service> -f   # View logs
```

### Common Log Locations
| Service | Log Location |
|---------|--------------|
| Liaison | `/var/log/liaison/` |
| WireGuard | `journalctl -u wg-quick@wg0` |
| OpenVPN | `/var/log/openvpn/` |
| SoftEther | `/opt/vpnserver/server_log/` |
| Suricata | `/var/log/suricata/` |
| Endlessh | `journalctl -u endlessh` |
| Chrony | `journalctl -u chrony` |
| Docker | `journalctl -u docker` |

### Firewall Quick Commands
```bash
# UFW (Ubuntu)
sudo ufw status
sudo ufw allow 22/tcp
sudo ufw deny 23/tcp
sudo ufw enable

# iptables
sudo iptables -L -n -v
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT
```

---

## Troubleshooting

### Service Won't Start
```bash
# Check service status
sudo systemctl status <service>

# View detailed logs
sudo journalctl -u <service> -n 50 --no-pager

# Check config syntax (service-specific)
sudo suricata -T -c /etc/suricata/suricata.yaml  # Suricata
sudo wg show  # WireGuard
```

### Port Already in Use
```bash
# Find what's using a port
sudo ss -tlnp | grep :<port>
sudo lsof -i :<port>

# Kill process using port
sudo kill $(sudo lsof -t -i:<port>)
```

### Permission Denied
```bash
# Check file permissions
ls -la /path/to/file

# Fix ownership
sudo chown root:root /path/to/file

# Fix permissions
sudo chmod 644 /path/to/file  # rw-r--r--
sudo chmod 755 /path/to/dir   # rwxr-xr-x
```

### Network Connectivity
```bash
# Test connectivity
ping -c 4 8.8.8.8

# Check DNS
nslookup google.com

# Check routes
ip route

# Check firewall
sudo iptables -L -n
sudo ufw status
```
