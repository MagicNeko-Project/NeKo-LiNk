![nekolink logo banner](./banner.png)

# NekoLink ฅ^•ﻌ•^ฅ

**NekoLink** is a high-performance, stealthy, and intelligent tunnel system based on the [WireGuard<sup>®</sup>](https://www.wireguard.com/) protocol. It is designed for portability and speed, with added support for custom IP protocols and automated key exchange.

The project consists of three parts:

*   **nekolink-core**: The core WireGuard implementation, supporting custom IP protocols (Raw IP mode).
*   **nekolink-cli**: A command-line userspace implementation.
*   **nekolink-ctl**: A smart control plane that automates configuration and public key exchange via encrypted signaling.

### Installation

You can install NekoLink using the provided `install.sh` script:

```bash
chmod +x install.sh
./install.sh
```

This will compile the projects and install the binaries to your system path.

### Configuration

You can use the interactive configuration helper:

```bash
neko-link
```

Or manually create JSON configurations in `/etc/neko-link/`.

### Running

To start the control plane and manage all tunnels:

```bash
nekolink-ctl
```

### Supported platforms

NekoLink supports Linux with identical behavior to the original userspace implementation, but with enhanced capabilities for Raw IP communication.

---

## License

The project is licensed under the [3-Clause BSD License](https://opensource.org/licenses/BSD-3-Clause).

---

**Note**: This project is modified based on the original [Boringtun](https://github.com/cloudflare/boringtun) project.

<sub><sub>WireGuard is a registered trademark of Jason A. Donenfeld. NekoLink is not sponsored or endorsed by Jason A. Donenfeld.</sub></sub>
