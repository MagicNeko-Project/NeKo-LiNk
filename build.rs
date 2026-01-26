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
                "-c", "src/bpf/xdp_kern.c",
                "-o"
            ])
            .arg(format!("{}/xdp_kern.o", out_dir))
            .status();
            
        if let Ok(s) = status {
            if !s.success() {
                println!("cargo:warning=Failed to compile BPF C code. AF_XDP will not work.");
                std::fs::write(format!("{}/xdp_kern.o", out_dir), []).unwrap();
            }
        } else {
             println!("cargo:warning=Failed to run clang. AF_XDP will not work.");
             std::fs::write(format!("{}/xdp_kern.o", out_dir), []).unwrap();
        }
    } else {
        println!("cargo:warning=Clang not found. AF_XDP will not work.");
        // Create dummy file
        let out_dir = env::var("OUT_DIR").unwrap();
        std::fs::write(format!("{}/xdp_kern.o", out_dir), []).unwrap();
    }
}
