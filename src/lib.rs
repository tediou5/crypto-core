#![allow(clippy::type_complexity)]
#![feature(closure_lifetime_binder)]

mod crypto;
pub use crypto::Cryptor;

mod raw_crypto;
pub use raw_crypto::RawCryptor;

mod error;
pub use error::Error;

pub mod x25519 {
    pub use x25519_dalek::{
        EphemeralSecret, PublicKey, ReusableSecret, SharedSecret, StaticSecret,
    };
}

const IPV4_MIN_HEADER_SIZE: usize = 20;
const IPV4_SRC_IP_OFF: usize = 12;
const IPV4_DST_IP_OFF: usize = 16;
const IPV4_IP_SZ: usize = 4;

const IPV6_MIN_HEADER_SIZE: usize = 40;
const IPV6_SRC_IP_OFF: usize = 8;
const IPV6_DST_IP_OFF: usize = 24;
const IPV6_IP_SZ: usize = 16;

pub fn dst_address(packet: &[u8]) -> Option<std::net::IpAddr> {
    if packet.is_empty() {
        return None;
    }
    match packet[0] >> 4 {
        4 if packet.len() >= IPV4_MIN_HEADER_SIZE => {
            let addr_bytes: [u8; IPV4_IP_SZ] = packet
                [IPV4_DST_IP_OFF..IPV4_DST_IP_OFF + IPV4_IP_SZ]
                .try_into()
                .unwrap();
            let addr = std::net::IpAddr::from(addr_bytes);
            Some(addr)
        }
        6 if packet.len() >= IPV6_MIN_HEADER_SIZE => {
            let addr_bytes: [u8; IPV6_IP_SZ] = packet
                [IPV6_DST_IP_OFF..IPV6_DST_IP_OFF + IPV6_IP_SZ]
                .try_into()
                .unwrap();
            let addr = std::net::IpAddr::from(addr_bytes);
            Some(addr)
        }
        _ => None,
    }
}

pub fn src_address(packet: &[u8]) -> Option<std::net::IpAddr> {
    if packet.is_empty() {
        return None;
    }
    match packet[0] >> 4 {
        4 if packet.len() >= IPV4_MIN_HEADER_SIZE => {
            let addr_bytes: [u8; IPV4_IP_SZ] = packet
                [IPV4_SRC_IP_OFF..IPV4_SRC_IP_OFF + IPV4_IP_SZ]
                .try_into()
                .unwrap();
            let addr = std::net::IpAddr::from(addr_bytes);
            Some(addr)
        }
        6 if packet.len() >= IPV6_MIN_HEADER_SIZE => {
            let addr_bytes: [u8; IPV6_IP_SZ] = packet
                [IPV6_SRC_IP_OFF..IPV6_SRC_IP_OFF + IPV6_IP_SZ]
                .try_into()
                .unwrap();
            let addr = std::net::IpAddr::from(addr_bytes);
            Some(addr)
        }
        _ => None,
    }
}

pub fn version() -> std::collections::HashMap<String, String> {
    std::collections::HashMap::from([("rf-crypto".to_string(), "1.0.3".to_string())])
}
