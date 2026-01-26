#!/bin/bash
set -e
export PATH=$HOME/.cargo/bin:$PATH

echo "=== Building NekoLink (Rust eBPF + bpf_crypto) ==="

# 1. Build Kernel BPF (using Nightly + bpf-linker)
echo "[*] Building Kernel BPF..."
RUSTC_BOOTSTRAP=1 cargo run --package xtask -- build-ebpf --release

# 2. Copy BPF bytes
echo "[*] Copying BPF bytes..."
cp neko-link/src/bpf_bytes.o neko-link/src/vpn/bpf_bytes.o

# 3. Build User Space
echo "[*] Building User Space..."
cargo build --package neko-link --release

# 4. Success Message
echo "=== Build Success! ==="
echo "Binary location: target/release/neko-link"
echo "To run:"
echo "  sudo ./target/release/neko-link --config config.json"
