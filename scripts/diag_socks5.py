#!/usr/bin/python3
# SOCKS5 深度诊断工具喵 v1.0
import socket
import struct
import sys
import time

def test_socks5(proxy_host, proxy_port, target_host, target_port):
    print(f"喵！正在通过 {proxy_host}:{proxy_port} 测试连接 {target_host}:{target_port}...")
    
    try:
        # 1. 连接代理
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((proxy_host, proxy_port))
        print("✓ 已连接到 SOCKS5 代理")

        # 2. 握手 (No Auth)
        s.sendall(b'\x05\x01\x00')
        resp = s.recv(2)
        if resp != b'\x05\x00':
            print(f"✗ 握手失败: {resp.hex()}")
            return

        # 3. 发送请求 (Connect)
        print(f"正在请求连接 {target_host}...")
        host_bytes = target_host.encode('utf-8')
        request = b'\x05\x01\x00\x03' + bytes([len(host_bytes)]) + host_bytes + struct.pack('>H', target_port)
        s.sendall(request)

        # 4. 获取响应
        start_time = time.time()
        resp = s.recv(10)
        end_time = time.time()
        
        if len(resp) < 4:
            print("✗ 代理未返回完整响应")
            return
            
        status = resp[1]
        if status == 0x00:
            print(f"✓ 连接成功！延迟: {(end_time - start_time)*1000:.2f}ms")
            # 试着读一点数据
            s.sendall(b"GET / HTTP/1.1\r\nHost: " + host_bytes + b"\r\n\r\n")
            data = s.recv(100)
            print(f"✓ 成功接收数据: {data[:20]}...")
        else:
            error_codes = {
                0x01: "常规失败 (General failure)",
                0x02: "规则集禁止 (Connection not allowed by ruleset)",
                0x03: "网络不可达 (Network unreachable)",
                0x04: "主机不可达 (Host unreachable)",
                0x05: "连接被拒 (Connection refused)",
                0x06: "TTL 过期 (TTL expired)",
                0x07: "命令不支持 (Command not supported)",
                0x08: "地址类型不支持 (Address type not supported)"
            }
            print(f"✗ 代理返回错误: {error_codes.get(status, f'未知内核错误 {status}')}")

    except Exception as e:
        print(f"✗ 异常: {e}")
    finally:
        s.close()

if __name__ == "__main__":
    if len(sys.argv) < 5:
        print("用法: python3 diag_socks5.py <代理IP> <代理端口> <目标主机> <目标端口>")
        sys.exit(1)
        
    test_socks5(sys.argv[1], int(sys.argv[2]), sys.argv[3], int(sys.argv[4]))
