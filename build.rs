use std::process::Command;
use std::env;

fn main() {
    println!("cargo:rerun-if-changed=src/bpf/xdp_kern.c");

    // Check if clang is available
    if Command::new("clang").arg("--version").output().is_ok() {
        let out_dir = env::var("OUT_DIR").unwrap();
        // Compile BPF
        let status = Command::new("clang")
            .args(&[
                "-O2", "-g", "-target", "bpf",
                "-I/usr/include/x86_64-linux-gnu",
                "-c", "src/bpf/xdp_kern.c",
                "-o"
            ])
            .arg(format!("{}/xdp_kern.o", out_dir))
             .status();
            
        // Compile TC BPF
        let status_tc = Command::new("clang")
            .args(&[
                "-O2", "-g", "-target", "bpf",
                "-I/usr/include/x86_64-linux-gnu",
                "-c", "src/bpf/tc_kern.c",
                "-o"
            ])
            .arg(format!("{}/tc_kern.o", out_dir))
            .status();

        if let Ok(s) = status {
            if !s.success() {
                println!("cargo:warning=Failed to compile XDP BPF code. AF_XDP will not work.");
                std::fs::write(format!("{}/xdp_kern.o", out_dir), []).unwrap();
            }
        } 
        
        if let Ok(s) = status_tc {
             if !s.success() {
                println!("cargo:warning=Failed to compile TC BPF code.");
                std::fs::write(format!("{}/tc_kern.o", out_dir), []).unwrap();
             }
        } else {
             // Clang failed for TC
             std::fs::write(format!("{}/tc_kern.o", out_dir), []).unwrap();
        }
    } else {
        println!("cargo:warning=Clang not found. AF_XDP will not work.");
        // Create dummy file
        let out_dir = env::var("OUT_DIR").unwrap();
        std::fs::write(format!("{}/xdp_kern.o", out_dir), []).unwrap();
        std::fs::write(format!("{}/tc_kern.o", out_dir), []).unwrap();
    }
}
