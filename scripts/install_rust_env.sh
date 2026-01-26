#!/bin/bash
set -e

echo ">>> 正在为 Neko-Link 准备 Rust 环境 (Debian 12/13)... 🐾"

# 1. 更新系统包
echo "Updating apt repositories..."
apt-get update

# 2. 安装基础依赖
echo "Installing base dependencies (Debian 13 Trixie/Sid)..."
# Try installing LLVM 19 explicitly.
apt-get install -y build-essential curl git pkg-config libssl-dev protobuf-compiler libbpf-dev \
    clang-19 llvm-19 libclang-19-dev llvm-19-dev libpolly-19-dev

# 3. 安装 Rust (如果不存在)
if ! command -v cargo &> /dev/null; then
    echo "Installing Rust via rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
else
    echo "Rust is already installed. Updating..."
    source "$HOME/.cargo/env"
    rustup update
fi

# 4. 设置默认工具链 (推荐 Stable)
echo "Setting default toolchain to stable..."
rustup default stable

# 5. 安装/检查绑定生成工具
echo "Installing bpf-linker (with llvm-19)..."
# Explicitly use llvm-19 feature for newer Debian versions
cargo install bpf-linker --no-default-features --features llvm-19

echo ">>> 环境准备完成! 喵! 🐾"
echo "请记得运行: source \"$HOME/.cargo/env\""
