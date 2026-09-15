# Splunk Server Setup

**Host:** Ubuntu — `192.168.100.120`

This covers installing Splunk Enterprise, enabling it as a boot-start service, opening the required firewall ports, and configuring the receiver inputs that the Linux and Windows forwarding guides depend on.

---

## 1. Install Dependencies & Set System Limits

**Prerequisites**

Update the package manager and install the tools needed for the install and firewall steps:

```bash
sudo apt-get update && sudo apt-get install -y wget tar ufw
```

## 2. Install Splunk Enterprise & Enable Boot Start

**Splunk Core**

Download, extract, and enable `splunkd` as a system service running under a dedicated non-root user:

```bash
# Download Splunk Debian package (or extract tarball to /opt/splunk)
cd /tmp
wget -O splunk-installer.deb \
  "https://download.splunk.com/products/splunk/releases/latest/linux/splunk-installer.deb"
sudo dpkg -i splunk-installer.deb

# Enable boot-start and accept license
sudo /opt/splunk/bin/splunk enable boot-start -user splunk --accept-license
sudo service splunk start
```

## 3. Configure Firewall Ports & Receivers

**Firewall & Receiver**

Open the required ports in UFW: Web UI (8000), Splunk Forwarders (9997), and Syslog (1514):

```bash
# Allow Splunk Web UI and Universal Forwarder receiver ports
sudo ufw allow 8000/tcp comment 'Splunk Web UI'
sudo ufw allow 9997/tcp comment 'Splunk Universal Forwarder Receiver'
sudo ufw allow 1514/udp comment 'Splunk Syslog Input'
sudo ufw reload
```

Enable receiving port 9997 in Splunk via CLI:

```bash
sudo /opt/splunk/bin/splunk enable listen 9997 -auth admin:<your_password>
```

## 4. Configure Port 514 → 1514 NAT Redirection

**Port Redirection**

To let non-root Splunk ingest standard UDP port 514 traffic, redirect incoming port 514 to port 1514 with `iptables`:

```bash
# Apply NAT redirect rule
sudo iptables -t nat -A PREROUTING -p udp --dport 514 -j REDIRECT --to-ports 1514

# Make rule persistent across reboots
sudo apt-get install -y iptables-persistent
sudo netfilter-persistent save
```

## 5. Configure UDP 1514 Data Input

**Splunk Web GUI**

- Log into Splunk Web (`http://192.168.100.120:8000`).
- Go to **Settings → Data Inputs → UDP**.
- Click **New Local UDP**, set **Port: 1514**, then click **Next**.
- Configure Input Settings — Source type: *Operating System → syslog*; App Context: *Search & Reporting (search)*; Host Method: *IP*; Index: *main*.
- Click **Review and Submit**.

---

*Next: [linux-log-forwarding.md](linux-log-forwarding.md) and [windows-log-forwarding.md](windows-log-forwarding.md) configure clients to send data to this receiver.*
