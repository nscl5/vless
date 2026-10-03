use wasm_bindgen::prelude::*;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
pub struct HeaderResult {
    pub has_error: bool,
    pub message: String,
    pub address_remote: String,
    pub port_remote: u16,
    pub raw_data_index: usize,
    pub is_udp: bool,
    pub version: u8,
}

pub fn parse_header(chunk: &[u8], user_ids: &str) -> HeaderResult {
    let mut result = HeaderResult {
        has_error: true,
        message: "invalid data".to_string(),
        address_remote: String::new(),
        port_remote: 0,
        raw_data_index: 0,
        is_udp: false,
        version: 0,
    };

    if chunk.len() < 24 {
        return result;
    }

    let version = chunk[0];
    result.version = version;

    let mut uuid_bytes = [0u8; 16];
    uuid_bytes.copy_from_slice(&chunk[1..17]);

    let client_uuid = format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        uuid_bytes[0], uuid_bytes[1], uuid_bytes[2], uuid_bytes[3],
        uuid_bytes[4], uuid_bytes[5],
        uuid_bytes[6], uuid_bytes[7],
        uuid_bytes[8], uuid_bytes[9],
        uuid_bytes[10], uuid_bytes[11], uuid_bytes[12], uuid_bytes[13], uuid_bytes[14], uuid_bytes[15]
    );

    let valid = user_ids.split(',').any(|id| id.trim().to_lowercase() == client_uuid);
    if !valid {
        result.message = "invalid user".to_string();
        return result;
    }

    let opt_length = chunk[17] as usize;
    let command_index = 18 + opt_length;
    if chunk.len() <= command_index {
        return result;
    }

    let command = chunk[command_index];
    if command != 1 && command != 2 {
        result.message = format!("command {} is not supported", command);
        return result;
    }
    result.is_udp = command == 2;

    let port_index = command_index + 1;
    if chunk.len() < port_index + 3 {
        return result;
    }

    let port_remote = ((chunk[port_index] as u16) << 8) | (chunk[port_index + 1] as u16);
    result.port_remote = port_remote;

    let address_type = chunk[port_index + 2];
    let mut current_idx = port_index + 3;

    match address_type {
        1 => {
            if chunk.len() < current_idx + 4 {
                return result;
            }
            result.address_remote = format!(
                "{}.{}.{}.{}",
                chunk[current_idx], chunk[current_idx + 1], chunk[current_idx + 2], chunk[current_idx + 3]
            );
            current_idx += 4;
        }
        2 => {
            if chunk.len() < current_idx + 1 {
                return result;
            }
            let address_length = chunk[current_idx] as usize;
            current_idx += 1;
            if chunk.len() < current_idx + address_length {
                return result;
            }
            if let Ok(domain) = std::str::from_utf8(&chunk[current_idx..current_idx + address_length]) {
                result.address_remote = domain.to_string();
            } else {
                result.message = "invalid domain utf-8".to_string();
                return result;
            }
            current_idx += address_length;
        }
        3 => {
            if chunk.len() < current_idx + 16 {
                return result;
            }
            let mut segments = Vec::new();
            for i in 0..8 {
                let idx = current_idx + i * 2;
                let val = ((chunk[idx] as u16) << 8) | (chunk[idx + 1] as u16);
                segments.push(format!("{:x}", val));
            }
            result.address_remote = segments.join(":");
            current_idx += 16;
        }
        _ => {
            result.message = format!("invalid addressType: {}", address_type);
            return result;
        }
    }

    result.has_error = false;
    result.message = "success".to_string();
    result.raw_data_index = current_idx;

    result
}

#[wasm_bindgen(js_name = processHeader)]
pub fn process_header(chunk: &[u8], user_ids: &str) -> JsValue {
    let result = parse_header(chunk, user_ids);
    serde_wasm_bindgen::to_value(&result).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_header_ipv6() {
        let user_id = "be0ff9df-1468-41a0-8865-796d1c6800db";
        let chunk = vec![
            0, // version
            0xbe, 0x0f, 0xf9, 0xdf, 0x14, 0x68, 0x41, 0xa0, 0x88, 0x65, 0x79, 0x6d, 0x1c, 0x68, 0x00, 0xdb, // uuid
            0, // opt len
            1, // cmd (TCP)
            0x01, 0xbb, // port 443
            3, // address_type = IPv6
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // 2001:db8::1
        ];

        let res = parse_header(&chunk, user_id);
        assert!(!res.has_error);
        assert_eq!(res.address_remote, "2001:db8:0:0:0:0:0:1");
        assert_eq!(res.port_remote, 443);
        assert!(!res.is_udp);
    }
}