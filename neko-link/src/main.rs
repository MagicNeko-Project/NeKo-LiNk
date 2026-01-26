mod config;
mod vpn;

use clap::Parser;
use config::Config;
use std::fs;
use std::path::Path;
use log::{error, LevelFilter};
use env_logger::Builder;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long, default_value = "config.json")]
    config: String,

    #[arg(long, default_value = "false")]
    debug: bool,
    
    #[arg(long, default_value = "false")]
    init: bool,
    
    #[arg(long, default_value = "server")]
    r#type: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Init Logger
    let mut builder = Builder::new();
    if args.debug {
        builder.filter_level(LevelFilter::Debug);
    } else {
        builder.filter_level(LevelFilter::Info);
    }
    builder.init();

    if args.init {
        generate_example_config(&args.r#type);
        return Ok(());
    }

    // Load Configs
    let default_config = "config.json";
    let etc_config = "/etc/neko-link";

    let config_path = if args.config == default_config && !Path::new(default_config).exists() && Path::new(etc_config).exists() {
        etc_config.to_string()
    } else {
        args.config.clone()
    };
    
    log::info!("Loading configuration from: {}", config_path);
    let configs = load_configs(&config_path)?;
    
    let mut tasks = Vec::new();
    
    for mut cfg in configs {
        if cfg.debug {
             // Re-init logger if needed, but usually global.
        }
        cfg.parse_legacy();
        
        // Spawn VPN Instance
        tasks.push(tokio::spawn(async move {
            if let Err(e) = vpn::run(cfg).await {
                error!("VPN Instance Error: {:?}", e);
            }
        }));
    }

    // Wait 
    for task in tasks {
        let _ = task.await;
    }

    Ok(())
}

fn load_configs(path: &str) -> anyhow::Result<Vec<Config>> {
    let p = Path::new(path);
    if !p.exists() {
        return Err(anyhow::anyhow!("Config file not found: {}", path));
    }

    let mut configs = Vec::new();

    if p.is_dir() {
        for entry in fs::read_dir(p)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().map(|s| s == "json").unwrap_or(false) {
                let content = fs::read_to_string(&path)?;
                if let Ok(c) = serde_json::from_str::<Vec<Config>>(&content) {
                    configs.extend(c);
                } else if let Ok(c) = serde_json::from_str::<Config>(&content) {
                    configs.push(c);
                } else {
                    error!("Failed to parse JSON: {:?}", path);
                }
            }
        }
    } else {
        let content = fs::read_to_string(p)?;
         if let Ok(c) = serde_json::from_str::<Vec<Config>>(&content) {
            configs.extend(c);
        } else if let Ok(c) = serde_json::from_str::<Config>(&content) {
            configs.push(c);
        } else {
            return Err(anyhow::anyhow!("Failed to parse config file"));
        }
    }

    if configs.is_empty() {
        return Err(anyhow::anyhow!("No valid config found"));
    }

    Ok(configs)
}

fn generate_example_config(mode: &str) {
    let mut cfg = Config {
        interface_name: "neko0".to_string(),
        mtu: 1400,
        debug: true,
        key: "CHANGE_ME_PLEASE_NYA_QAQ".to_string(),
        protocol: "raw".to_string(),
        ip_protocol_num: 233,
        ..Default::default()
    };
    
    if mode == "client" {
        cfg.mode = "client".to_string();
        cfg.local_addr_v4 = "192.168.100.2/24".to_string();
        cfg.peer_addr = "SERVER_IP".to_string();
    } else {
        cfg.mode = "server".to_string();
        cfg.local_addr_v4 = "192.168.100.1/24".to_string();
        cfg.peer_addr = "CLIENT_IP".to_string();
    }
    
    let json = serde_json::to_string_pretty(&vec![cfg]).unwrap();
    println!("{}", json);
    
    // In real impl, we would write to file.
    let _ = fs::write("config.json", json);
}
