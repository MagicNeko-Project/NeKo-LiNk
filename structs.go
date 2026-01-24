package main

import (
	"net"
)

// Job 代表一个待处理的数据包任务
type Job struct {
	ID       int           // Batch 中的索引，用于重组顺序
	Plain    []byte        // 原始数据 (从 TUN 读入)
	Enc      []byte        // 加密数据 (从 Net 读入)
	Nonce    []byte        // 用于解密的 Nonce
	Addr     net.Addr      // 远端地址 (ClientRemoteUDP 或 ServerPeerAddr)
	Type     int           // 0: Encrypt (TUN->Net), 1: Decrypt (Net->TUN)
	Callback func([]byte)  // 处理完成后的回调 (如 WriteToUDP)
}

// Result 代表处理完成的结果
type Result struct {
	ID         int
	Data       []byte
	Addr       net.Addr
	Err        error
	RecyclePtr *[]byte // 用于回收的原始指针
}
