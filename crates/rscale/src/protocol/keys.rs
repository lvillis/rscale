use std::fmt::Write as _;

use graviola::key_agreement::x25519::StaticPrivateKey;

use crate::error::{AppError, AppResult};

const MACHINE_PRIVATE_PREFIX: &str = "privkey:";
const MACHINE_PUBLIC_PREFIX: &str = "mkey:";
const NODE_PUBLIC_PREFIX: &str = "nodekey:";
const CHALLENGE_PUBLIC_PREFIX: &str = "chalpub:";

pub fn parse_machine_private_key(value: &str) -> AppResult<[u8; 32]> {
    parse_typed_hex_key(value, MACHINE_PRIVATE_PREFIX)
}

pub fn parse_node_private_key(value: &str) -> AppResult<[u8; 32]> {
    parse_typed_hex_key(value, MACHINE_PRIVATE_PREFIX)
}

pub fn machine_public_key_from_private(private_key: &[u8; 32]) -> String {
    let private_key = StaticPrivateKey::from_array(private_key);
    let public_key = private_key.public_key();
    encode_typed_hex_key(MACHINE_PUBLIC_PREFIX, &public_key.as_bytes())
}

pub fn machine_public_key_from_raw(raw: &[u8; 32]) -> String {
    encode_typed_hex_key(MACHINE_PUBLIC_PREFIX, raw)
}

pub fn node_public_key_from_private(private_key: &[u8; 32]) -> String {
    let private_key = StaticPrivateKey::from_array(private_key);
    let public_key = private_key.public_key();
    encode_typed_hex_key(NODE_PUBLIC_PREFIX, &public_key.as_bytes())
}

pub fn node_public_key_from_raw(raw: &[u8; 32]) -> String {
    encode_typed_hex_key(NODE_PUBLIC_PREFIX, raw)
}

pub fn parse_node_public_key(value: &str) -> AppResult<[u8; 32]> {
    parse_typed_hex_key(value, NODE_PUBLIC_PREFIX)
}

pub fn raw_key_hex(raw: &[u8]) -> String {
    encode_typed_hex_key("", raw)
}

pub fn generate_challenge_public_key() -> AppResult<String> {
    let private_key = StaticPrivateKey::new_random()
        .map_err(|err| AppError::Bootstrap(format!("failed to generate challenge key: {err}")))?;
    let public_key = private_key.public_key();
    Ok(encode_typed_hex_key(
        CHALLENGE_PUBLIC_PREFIX,
        &public_key.as_bytes(),
    ))
}

fn parse_typed_hex_key(value: &str, prefix: &str) -> AppResult<[u8; 32]> {
    let encoded = value
        .strip_prefix(prefix)
        .ok_or_else(|| AppError::InvalidConfig(format!("key must start with {prefix}")))?;

    if encoded.len() != 64 {
        return Err(AppError::InvalidConfig(format!(
            "key with prefix {prefix} must contain exactly 64 hex characters"
        )));
    }

    let mut bytes = [0_u8; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        let offset = index * 2;
        let chunk = &encoded[offset..offset + 2];
        *byte = u8::from_str_radix(chunk, 16).map_err(|err| {
            AppError::InvalidConfig(format!("failed to decode key with prefix {prefix}: {err}"))
        })?;
    }

    Ok(bytes)
}

fn encode_typed_hex_key(prefix: &str, raw: &[u8]) -> String {
    let mut value = String::with_capacity(prefix.len() + raw.len() * 2);
    value.push_str(prefix);
    for byte in raw {
        let _ = write!(value, "{byte:02x}");
    }
    value
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::*;

    const PRIVATE_KEY: &str =
        "privkey:1111111111111111111111111111111111111111111111111111111111111111";

    #[test]
    fn parse_machine_private_key_accepts_valid_typed_hex() -> Result<(), Box<dyn Error>> {
        let parsed = parse_machine_private_key(PRIVATE_KEY)?;
        assert_eq!(parsed, [0x11; 32]);
        Ok(())
    }

    #[test]
    fn parse_node_public_key_rejects_wrong_prefix_and_length() -> Result<(), Box<dyn Error>> {
        let wrong_prefix = match parse_node_public_key(
            "mkey:1111111111111111111111111111111111111111111111111111111111111111",
        ) {
            Ok(_) => return Err(std::io::Error::other("wrong prefix should be rejected").into()),
            Err(err) => err,
        };
        assert!(
            matches!(wrong_prefix, AppError::InvalidConfig(message) if message.contains("nodekey:"))
        );

        let wrong_len = match parse_node_public_key("nodekey:abcd") {
            Ok(_) => return Err(std::io::Error::other("short key should be rejected").into()),
            Err(err) => err,
        };
        assert!(
            matches!(wrong_len, AppError::InvalidConfig(message) if message.contains("exactly 64 hex characters"))
        );
        Ok(())
    }

    #[test]
    fn public_key_helpers_encode_expected_prefixes() -> Result<(), Box<dyn Error>> {
        let private_key = parse_machine_private_key(PRIVATE_KEY)?;
        let machine_public = machine_public_key_from_private(&private_key);
        let node_public = node_public_key_from_private(&private_key);

        assert!(machine_public.starts_with(MACHINE_PUBLIC_PREFIX));
        assert!(node_public.starts_with(NODE_PUBLIC_PREFIX));
        assert_eq!(machine_public.len(), MACHINE_PUBLIC_PREFIX.len() + 64);
        assert_eq!(node_public.len(), NODE_PUBLIC_PREFIX.len() + 64);
        Ok(())
    }

    #[test]
    fn node_public_key_round_trips_from_private_to_raw() -> Result<(), Box<dyn Error>> {
        let private_key = parse_machine_private_key(PRIVATE_KEY)?;
        let encoded = node_public_key_from_private(&private_key);
        let parsed = parse_node_public_key(&encoded)?;
        assert_eq!(encoded, node_public_key_from_raw(&parsed));
        Ok(())
    }

    #[test]
    fn raw_key_hex_does_not_include_a_prefix() {
        assert_eq!(raw_key_hex(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
    }

    #[test]
    fn generate_challenge_public_key_uses_challenge_prefix() -> Result<(), Box<dyn Error>> {
        let challenge = generate_challenge_public_key()?;
        assert!(challenge.starts_with(CHALLENGE_PUBLIC_PREFIX));
        assert_eq!(challenge.len(), CHALLENGE_PUBLIC_PREFIX.len() + 64);
        Ok(())
    }
}
