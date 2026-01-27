# NekoLink: High-Performance Stealth Magic Tunnel ฅ^•ﻌ•^ฅ

![NekoLink Banner](./banner.png)

**NekoLink** is a high-performance, stealthy, and intelligent tunnel system based on a highly customized [WireGuard®](https://www.wireguard.com/) protocol implementation. It inherits the extreme speed of WireGuard while adding unique "magic" features to help you navigate complex network environments with ease.

---

## 🌟 Core Features

- **🚀 Custom IP Protocol (Raw IP Mode)**: Break free from UDP (Protocol 17) throttling and identification! You can communicate directly using any IP protocol number between 1 and 255. In this mode, **NekoLink is 100% UDP-free**, as even the signaling/key-exchange is performed over Raw IP. Firewalls won't even know what hit them!
- **🎭 Fake-TCP Stealth Mode (Fake-TCP Mode)**: The ultimate penetration magic! By masquerading all traffic as legitimate TCP packets (including full handshake simulation and state management), your data flows appear like regular web browsing to network monitors.
- **🤝 Automated Key Exchange**: No more manually copying and pasting long public keys. As long as the Pre-Shared Keys (PSK) match, NekoLink will automatically exchange WireGuard public keys via an encrypted signaling channel. In IP/TCP mode, this channel automatically reuses your transport mechanism.
- **🎮 Interactive Config Helper (`neko-link`)**: A user-friendly wizard that guides you through server/client setup and generates JSON configurations automatically.
- **🛡️ Routing Safety (Table=off Logic)**: By default, NekoLink does not modify the system routing table. This prevents total connectivity loss caused by aggressive `0.0.0.0/0` configurations.
- **💤 Smart Halt & Keepalive**: For maximum stealth, signaling exchange permanently enters deep sleep once connected. Combined with native WireGuard Keepalive, the tunnel remains bulletproof and nearly invisible.
- **🦀 Pure Rust Implementation**: From the core driver to the control plane, everything is written in Rust for memory safety and blazing-fast performance.
- **📡 Adaptive MTU Discovery**: Automatically detects the PMTU of your network path and recommends the best MTU for the tunnel.

---

## 🏗️ Architecture

1. **nekolink-core**: The engine library with Raw IP protocol support.
2. **nekolink-cli**: The command-line utility for encryption and decryption.
3. **nekolink-ctl**: The intelligent control plane that manages configurations, key generation, signaling, and tunnel lifecycle.
4. **neko-link.sh**: Your interactive guide for generating configurations.

---

## 🛠️ Installation

Run the universal installation script from the project root:

```bash
chmod +x install.sh
sudo ./install.sh
```

### ⛵ Smooth Update
To update an existing installation without losing your configurations, use the dedicated upgrade script:
```bash
chmod +x update.sh
sudo ./update.sh
```

> [!TIP]
> The update script automatically handles process termination and preserves everything in `/etc/neko-link/`. It also fetches the latest code from the repository.

---

## 📖 Quick Start

### 1. Interactive Setup (Recommended)
Simply run the following command and follow the prompts:
```bash
nekolink
```
Choose your role (Server/Client), transmission mode (IP or UDP), protocol number, and internal IP address.

### 2. Manage Tunnels
Once configured, use systemd to manage the NekoLink service:

```bash
# Start the service
sudo systemctl start nekolink

# Stop the service
sudo systemctl stop nekolink

# View real-time logs
journalctl -u nekolink -f

# Enable/Disable auto-start on boot
sudo systemctl enable/disable nekolink
```

You can also run `nekolink-ctl` directly for foreground debugging. It will automatically scan and manage all configurations located in `/etc/neko-link/*.json` in parallel.

---

## 📝 Configuration Reference

Manual configurations are stored in `/etc/neko-link/*.json`.

```json
{
  "interface": "nekotun0",
  "mode": "ip",
  "ip_protocol": 141,
  "listen_port": null,
  "auto_route": false,
  "local_address": "10.0.0.1/24",
  "psk": "Your_Secret_Key",
  "peers": [
    { "endpoint": "PEER_PUBLIC_IP:5678" }
  ],
  "signal_port": 5678
}
```

| Parameter | Description | Recommended |
| :--- | :--- | :--- |
| `interface` | Virtual network interface name | Default: `nekotun0` |
| `mode` | `ip` (Raw IP), `udp` (Standard Mode) or `tcp` (Fake-TCP). Used for both **Data and Signaling**. | Use `ip` or `tcp` to bypass UDP blocks |
| `ip_protocol`| Protocol number for Raw IP mode | Use 143-252 for experimentation |
| `listen_port` | WireGuard listen port (UDP mode) | Set to `null` in `ip/tcp` mode |
| `auto_route` | Modify system routing table? | Default `false` for safety |
| `local_address`| Tunnel internal IP (CIDR) | e.g., `10.0.0.1/24` |
| `psk` | Pre-Shared Key for automated signaling | Must match on both ends! |
| `peers` | Peer information. In `ip/tcp` mode, just use the **Public IP**. | e.g., `{"endpoint": "1.2.3.4"}` |
| `persistent_keepalive` | **Activity Interval** (seconds). Keeps the NAT mapping alive. | Recommended: `25` |
| `mtu` | **Tunnel Interface MTU**. Defaults to `1420` for optimal encapsulation. | Recommended: `1420` |
| `signal_port` | **Signaling Port** (UDP) | Only used in `udp` mode. Ignored in `ip/tcp` mode. |

---

## ⚠️ Important Notes

1. **Firewalls**: Ensure your selected `ip_protocol` and `signal_port` (UDP) are open in your server's firewall.
2. **Permissions**: While `install.sh` sets caps, `sudo` is still recommended for network interface operations.

---

## 🔍 How to Verify IP Mode?

You can use `tcpdump` to observe traffic on your physical interface.

Assuming your physical interface is `eth0` and your `ip_protocol` is `141`:

```bash
# Capture packets with the specific protocol number
sudo tcpdump -i eth0 proto 141 -n -v
```

**What to look for:**
- Packets with protocol `141` on the physical interface.
- No UDP traffic (unless in `udp` mode).
- Interface MTU set to `1420` (check with `ip link show nekotun0`).

---

## 📜 Credits & License

- **Based on Original Project**: This project is deeply customized and modified based on the original [Boringtun](https://github.com/cloudflare/boringtun) implementation by Cloudflare.
- **License**: Inherited [3-Clause BSD License](./LICENSE.md).
- **Trademark**: WireGuard® is a registered trademark of Jason A. Donenfeld. NekoLink is not affiliated with or endorsed by Jason A. Donenfeld.

---

May your packets be as agile as a Neko! ฅ^•ﻌ•^ฅ
