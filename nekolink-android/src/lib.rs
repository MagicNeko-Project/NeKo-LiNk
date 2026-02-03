// use jni::parse::PType;
use jni::sys::jstring;
use jni::JNIEnv;
use jni::objects::{JClass, JString, JObject, JValue};
use std::ffi::CStr;
use std::time::Duration;
use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use blake2::{Blake2s256, Digest};
use chacha20poly1305::{aead::{Aead, KeyInit}, ChaCha20Poly1305, Nonce};
use rand::RngCore;
use tokio::net::UdpSocket;
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
struct HandshakeResult {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    peer_pub_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mtu: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

fn derive_cipher(psk: &str) -> ChaCha20Poly1305 {
    let mut psk_bytes = [0u8; 32];
    let salt = b"NekoLink_Magic_Salt";
    let mut hasher = Blake2s256::new();
    hasher.update(psk.as_bytes());
    hasher.update(salt);
    let derived_key = hasher.finalize();
    psk_bytes.copy_from_slice(&derived_key);
    ChaCha20Poly1305::new(&psk_bytes.into())
}

fn decode_base64_safe(s: &str) -> Result<Vec<u8>> {
    let s = s.trim();
    if let Ok(b) = BASE64.decode(s) {
        return Ok(b);
    }
    let mut padded = s.to_string();
    padded = padded.trim_end_matches('=').to_string();
    while padded.len() % 4 != 0 {
        padded.push('=');
    }
    BASE64.decode(&padded).context("Base64 decode failed")
}


async fn perform_handshake_internal(server_addr: String, psk: String, my_pub_key: String) -> Result<HandshakeResult> {
    // 1. Prepare Socket
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    // socket.set_read_buffer_size(1024 * 64)?; // Not available on tokio UdpSocket directly
    
    // Resolve signaling address (assume server_addr is IP, check for port 12580)
    let target = if server_addr.contains(':') {
        server_addr.clone()
    } else {
        format!("{}:12580", server_addr)
    };
    
    // 2. Prepare Payload
    let cipher = derive_cipher(&psk);
    let my_pub_bytes = decode_base64_safe(&my_pub_key)?;
    
    if my_pub_bytes.len() != 32 {
        return Err(anyhow::anyhow!("Invalid public key length"));
    }

    let mut msg_base = my_pub_bytes;
    // Android side: We don't really know our MTU or listening port yet in this context, 
    // or we can send 0/0 and let the server decide or ignore.
    // Based on `nekolink-ctl` logic: msg.extend(mtu); msg.extend(tunnel_port);
    msg_base.extend_from_slice(&0u16.to_be_bytes()); // MTU placeholder
    msg_base.extend_from_slice(&0u16.to_be_bytes()); // Port placeholder (client behind NAT usually 0)

    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    
    let ciphertext = cipher.encrypt(Nonce::from_slice(&nonce_bytes), msg_base.as_slice())
        .map_err(|e| anyhow::anyhow!("Encryption failed"))?;
        
    let mut pkt = nonce_bytes.to_vec();
    pkt.extend_from_slice(&ciphertext);
    
    // 3. Send
    socket.send_to(&pkt, &target).await?;
    
    // 4. Receive
    let mut buf = [0u8; 2048];
    let (len, _src) = tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut buf)).await??;
    
    if len < 12 + 32 {
        return Err(anyhow::anyhow!("Response too short"));
    }
    
    let (nonce_part, encrypted_part) = buf[..len].split_at(12);
    let nonce = Nonce::from_slice(nonce_part);
    
    let decrypted = cipher.decrypt(nonce, encrypted_part)
        .map_err(|e| anyhow::anyhow!("Decryption failed"))?;
        
    if decrypted.len() < 36 {
        return Err(anyhow::anyhow!("Decrypted payload too short"));
    }
    
    // 5. Parse Response
    // [ServerPubKey(32)][MTU(2)][RealPort(2)]
    let server_pub_key = BASE64.encode(&decrypted[..32]);
    let mtu = u16::from_be_bytes([decrypted[32], decrypted[33]]);
    let real_port = u16::from_be_bytes([decrypted[34], decrypted[35]]);
    
    // Construct real endpoint
    let server_ip = target.split(':').next().unwrap_or(&target);
    let real_endpoint = format!("{}:{}", server_ip, real_port);
    
    Ok(HandshakeResult {
        success: true,
        peer_pub_key: Some(server_pub_key),
        endpoint: Some(real_endpoint),
        mtu: Some(mtu),
        error: None,
    })
}

#[no_mangle]
pub extern "system" fn Java_com_wireguard_android_backend_GoBackend_nekoSignal<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    server_addr: JString<'local>,
    psk: JString<'local>,
    my_pub_key: JString<'local>,
) -> JString<'local> {
    // Initialize logger if not already
    let _ = android_logger::init_once(
        android_logger::Config::default().with_max_level(log::LevelFilter::Info),
    );

    let server_addr: String = env.get_string(&server_addr).expect("Invalid server_addr").into();
    let psk: String = env.get_string(&psk).expect("Invalid psk").into();
    let my_pub_key: String = env.get_string(&my_pub_key).expect("Invalid pub_key").into();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let result = rt.block_on(perform_handshake_internal(server_addr, psk, my_pub_key));

    let response = match result {
        Ok(res) => res,
        Err(e) => HandshakeResult {
            success: false,
            peer_pub_key: None,
            endpoint: None,
            mtu: None,
            error: Some(e.to_string()),
        }
    };

    let json_str = serde_json::to_string(&response).unwrap_or_else(|_| "{\"success\":false,\"error\":\"JSON serialization failed\"}".to_string());
    
    env.new_string(json_str).expect("Could not create java string")
}
