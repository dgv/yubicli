use std::fmt;

pub const YUBICO_OATH_AID: &[u8] = &[0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01];

pub const TAG_NAME: u8 = 0x71;
pub const TAG_NAME_LIST: u8 = 0x72;
pub const TAG_KEY: u8 = 0x73;
pub const TAG_CHALLENGE: u8 = 0x74;
pub const TAG_RESPONSE: u8 = 0x75;
pub const TAG_TRUNCATED: u8 = 0x76;
pub const TAG_HOTP: u8 = 0x77;
pub const TAG_PROPERTY: u8 = 0x78;
pub const TAG_VERSION: u8 = 0x79;
pub const TAG_IMF: u8 = 0x7A;
pub const TAG_TOUCH: u8 = 0x7C;

pub const INS_LIST: u8 = 0xA1;
pub const INS_PUT: u8 = 0x01;
pub const INS_DELETE: u8 = 0x02;
pub const INS_SET_CODE: u8 = 0x03;
pub const INS_RESET: u8 = 0x04;
pub const INS_CALCULATE: u8 = 0xA2;
pub const INS_VALIDATE: u8 = 0xA3;
pub const INS_CALCULATE_ALL: u8 = 0xA4;
pub const INS_SEND_REMAINING: u8 = 0xA5;

pub const MASK_TYPE: u8 = 0xF0;
pub const HMAC_MINIMUM_KEY_SIZE: usize = 14;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algorithm {
    Sha1 = 0x01,
    Sha256 = 0x02,
    Sha512 = 0x03,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OathType {
    Hotp = 0x10,
    Totp = 0x20,
}

impl OathType {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val & MASK_TYPE {
            0x10 => Some(OathType::Hotp),
            0x20 => Some(OathType::Totp),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Version {
    pub major: u8,
    pub minor: u8,
    pub patch: u8,
}

impl Version {
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() == 3 {
            Some(Version {
                major: data[0],
                minor: data[1],
                patch: data[2],
            })
        } else {
            None
        }
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Credential {
    pub id: Vec<u8>,
    pub issuer: Option<String>,
    pub name: String,
    pub oath_type: OathType,
    pub period: u32,
    pub digits: u8,
    pub algorithm: Algorithm,
    pub touch_required: bool,
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct Code {
    pub value: String,
    pub valid_from: u64,
    pub valid_to: u64,
}

pub fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(2 + value.len());
    result.push(tag);
    if value.len() < 0x80 {
        result.push(value.len() as u8);
    } else if value.len() < 0x100 {
        result.push(0x81);
        result.push(value.len() as u8);
    } else {
        result.push(0x82);
        result.push((value.len() >> 8) as u8);
        result.push(value.len() as u8);
    }
    result.extend_from_slice(value);
    result
}

pub fn parse_tlvs(data: &[u8]) -> Vec<(u8, &[u8])> {
    let mut result = Vec::new();
    let mut pos = 0;
    while pos + 2 <= data.len() {
        let tag = data[pos];
        pos += 1;
        let len_byte = data[pos] as usize;
        pos += 1;
        let len = if len_byte < 0x80 {
            len_byte
        } else if len_byte == 0x81 {
            if pos >= data.len() {
                break;
            }
            let l = data[pos] as usize;
            pos += 1;
            l
        } else if len_byte == 0x82 {
            if pos + 1 >= data.len() {
                break;
            }
            let l = ((data[pos] as usize) << 8) | (data[pos + 1] as usize);
            pos += 2;
            l
        } else {
            break;
        };
        if pos + len > data.len() {
            break;
        }
        result.push((tag, &data[pos..pos + len]));
        pos += len;
    }
    result
}

pub fn parse_cred_id(cred_id: &[u8], oath_type: OathType) -> (Option<String>, String, u32) {
    let s = String::from_utf8_lossy(cred_id);
    match oath_type {
        OathType::Totp => {
            let mut remaining: &str = &s;
            let mut period = 30u32;

            if let Some(slash_pos) = remaining.find('/') {
                if let Ok(p) = remaining[..slash_pos].parse::<u32>() {
                    period = p;
                    remaining = &remaining[slash_pos + 1..];
                }
            }

            if let Some(colon_pos) = remaining.find(':') {
                let issuer = Some(remaining[..colon_pos].to_string());
                let name = remaining[colon_pos + 1..].to_string();
                (issuer, name, period)
            } else {
                (None, remaining.to_string(), period)
            }
        }
        OathType::Hotp => {
            if s.contains(':') && !s.starts_with(':') {
                let parts: Vec<&str> = s.splitn(2, ':').collect();
                (Some(parts[0].to_string()), parts[1].to_string(), 0)
            } else {
                (None, s.to_string(), 0)
            }
        }
    }
}

pub fn format_cred_id(issuer: Option<&str>, name: &str, oath_type: OathType, period: u32) -> Vec<u8> {
    let mut id = String::new();
    if oath_type == OathType::Totp && period != 30 {
        id.push_str(&format!("{}/", period));
    }
    if let Some(iss) = issuer {
        id.push_str(iss);
        id.push(':');
    }
    id.push_str(name);
    id.into_bytes()
}

pub fn get_device_id(salt: &[u8]) -> String {
    use sha2::Digest;

    let mut hasher = sha2::Sha256::new();
    hasher.update(salt);
    let hash = hasher.finalize();
    let encoded = data_encoding::BASE64.encode(&hash[..16]);
    encoded.trim_end_matches('=').to_string()
}

pub fn derive_key(salt: &[u8], passphrase: &str) -> Vec<u8> {
    use pbkdf2::pbkdf2_hmac;
    use sha1::Sha1;

    let mut key = [0u8; 16];
    pbkdf2_hmac::<Sha1>(passphrase.as_bytes(), salt, 1000, &mut key);
    key.to_vec()
}

pub fn hmac_sha1(key: &[u8], data: &[u8]) -> Vec<u8> {
    use hmac::Mac;
    use sha1::Sha1;

    let mut mac = hmac::Hmac::<Sha1>::new_from_slice(key).unwrap();
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

pub fn hmac_shorten_key(key: &[u8], algo: Algorithm) -> Vec<u8> {
    use sha2::Digest;

    match algo {
        Algorithm::Sha1 => {
            if key.len() < 64 {
                key.to_vec()
            } else {
                let mut hasher = sha1::Sha1::new();
                hasher.update(key);
                hasher.finalize().to_vec()
            }
        }
        Algorithm::Sha256 => {
            if key.len() < 64 {
                key.to_vec()
            } else {
                let mut hasher = sha2::Sha256::new();
                hasher.update(key);
                hasher.finalize().to_vec()
            }
        }
        Algorithm::Sha512 => {
            if key.len() < 128 {
                key.to_vec()
            } else {
                let mut hasher = sha2::Sha512::new();
                hasher.update(key);
                hasher.finalize().to_vec()
            }
        }
    }
}

pub fn get_challenge(timestamp: u64, period: u32) -> Vec<u8> {
    let time_step = timestamp / period as u64;
    (time_step as i64).to_be_bytes().to_vec()
}

pub fn format_code_from_truncated(truncated: &[u8]) -> String {
    if truncated.len() < 5 {
        return String::new();
    }
    let digits = truncated[0];
    let code_bytes = &truncated[1..5];
    let code = u32::from_be_bytes([code_bytes[0], code_bytes[1], code_bytes[2], code_bytes[3]]);
    let modulo = 10u32.pow(digits as u32);
    format!("{:0>width$}", code % modulo, width = digits as usize)
}
