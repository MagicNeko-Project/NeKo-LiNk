pub(crate) struct KeyBytes(pub [u8; 32]);

impl std::str::FromStr for KeyBytes {
    type Err = &'static str;

    /// Can parse a secret key from a hex or base64 encoded string.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut internal = [0u8; 32];

        match s.len() {
            64 => {
                // Try to parse as hex
                for i in 0..32 {
                    internal[i] = u8::from_str_radix(&s[i * 2..=i * 2 + 1], 16)
                        .map_err(|_| "Illegal character in key")?;
                }
            }
            43 | 44 => {
                // Try to parse as base64
                if let Ok(decoded_key) = base64::decode(s) {
                    if decoded_key.len() == internal.len() {
                        internal[..].copy_from_slice(&decoded_key);
                    } else {
                        return Err("Illegal character in key");
                    }
                } else {
                    return Err("Illegal character in key");
                }
            }
            _ => return Err("Illegal key size"),
        }

        Ok(KeyBytes(internal))
    }
}

// 给它找活干：增加转换到 x25519 类型的能力喵！
impl From<KeyBytes> for crate::x25519::StaticSecret {
    fn from(key: KeyBytes) -> Self {
        crate::x25519::StaticSecret::from(key.0)
    }
}

impl From<KeyBytes> for crate::x25519::PublicKey {
    fn from(key: KeyBytes) -> Self {
        crate::x25519::PublicKey::from(key.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_key_bytes_parsing() {
        // 测试 Base64 解析喵
        let b64 = "YmFzZTY0IGlzIGEgdmVyeSBvcmRpbmFyeSBrZXkgISE=";
        let key = KeyBytes::from_str(b64).expect("Base64 解析失败喵");
        assert_eq!(key.0.len(), 32);

        // 测试 Hex 解析喵
        let hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let key_hex = KeyBytes::from_str(hex).expect("Hex 解析失败喵");
        assert_eq!(key_hex.0[0], 0x01);
        assert_eq!(key_hex.0[31], 0xef);
    }
}
