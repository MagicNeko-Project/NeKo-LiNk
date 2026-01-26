use std::process::Command;
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser)]
enum Options {
    BuildEbpf {
        #[clap(long)]
        release: bool,
    },
}

fn main() -> anyhow::Result<()> {
    let opts = Options::parse();
    match opts {
        Options::BuildEbpf { release } => {
            build_ebpf(release)?;
        }
    }
    Ok(())
}

fn build_ebpf(release: bool) -> anyhow::Result<()> {
    let mut args = vec![
        "build",
        "--package", "neko-link-ebpf",
        "--target", "bpfel-unknown-none",
        "-Z", "build-std=core",
    ];

    if release {
        args.push("--release");
    }

    let status = Command::new("cargo")
        .env("RUSTC_BOOTSTRAP", "1") // Ensure nightly features are available inside the command
        .args(&args)
        .status()?;

    if !status.success() {
        anyhow::bail!("Failed to build eBPF programs using cargo");
    }

    let profile = if release { "release" } else { "debug" };
    
    // The output binary name matches the package name "neko-link-ebpf"
    let src = PathBuf::from("target")
        .join("bpfel-unknown-none")
        .join(profile)
        .join("neko-link-ebpf"); 

    if !src.exists() {
        anyhow::bail!("Source file not found at expected path: {:?}", src);
    }
    
    // Strip the binary
    let status_strip = Command::new("llvm-strip")
        .args(&["-g", src.to_str().unwrap()])
        .status();

    if let Err(e) = status_strip {
        println!("Warning: failed to run llvm-strip: {}", e);
    }

    let dst = PathBuf::from("neko-link")
        .join("src")
        .join("vpn")
        .join("bpf_bytes.o");

    std::fs::copy(&src, &dst)?;
    println!("Copied {:?} to {:?}", src, dst);
    
    Ok(())
}
