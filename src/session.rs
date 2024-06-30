use pcsc::*;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::oath::*;

const SW_SUCCESS: u16 = 0x9000;
const SW_INCORRECT_PARAMS: u16 = 0x6A80;

const MGMT_AID: &[u8] = &[0xA0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17];
const OTP_AID: &[u8] = &[0xA0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01];
const INS_READ_CONFIG: u8 = 0x1D;

const TAG_SERIAL: u8 = 0x02;
const TAG_USB_ENABLED: u8 = 0x03;
const TAG_FORM_FACTOR: u8 = 0x04;
const TAG_NFC_ENABLED: u8 = 0x0E;

const CAP_OTP: u16 = 0x01;
const CAP_U2F: u16 = 0x02;
const CAP_OATH: u16 = 0x20;
const CAP_PIV: u16 = 0x10;
const CAP_OPENPGP: u16 = 0x08;
const CAP_FIDO2: u16 = 0x200;
const CAP_HSMAUTH: u16 = 0x100;

#[derive(Debug)]
pub struct DeviceInfo {
    pub device_type: String,
    pub serial: u32,
    pub firmware_version: Version,
    pub interfaces: String,
    #[allow(dead_code)]
    pub usb_enabled: bool,
    #[allow(dead_code)]
    pub nfc_enabled: bool,
}

impl DeviceInfo {
    pub fn query(card: &mut Card) -> Result<Self> {
        let mut buf = [0; MAX_BUFFER_SIZE_EXTENDED];

        if let Ok(info) = Self::query_mgmt(card, &mut buf) {
            return Ok(info);
        }

        Self::query_otp(card, &mut buf)
    }

    fn query_mgmt(card: &mut Card, buf: &mut [u8]) -> Result<Self> {
        let mut apdu = Vec::new();
        apdu.push(0x00);
        apdu.push(0xA4);
        apdu.push(0x04);
        apdu.push(0x00);
        apdu.push(MGMT_AID.len() as u8);
        apdu.extend_from_slice(MGMT_AID);
        apdu.push(0x00);

        let rapdu = card.transmit(&apdu, buf)?;
        if rapdu.len() < 2 {
            return Err(Error::Parse("Response too short".into()));
        }
        let sw = ((rapdu[rapdu.len() - 2] as u16) << 8) | (rapdu[rapdu.len() - 1] as u16);
        if sw != SW_SUCCESS {
            return Err(Error::Parse("Management app not available".into()));
        }

        let select_data = &rapdu[..rapdu.len() - 2];
        let mut fw_version = if let Ok(s) = std::str::from_utf8(select_data) {
            if let Some(pos) = s.rfind("version ") {
                let version_str = &s[pos + 8..];
                let parts: Vec<&str> = version_str.split('.').collect();
                if parts.len() >= 2 {
                    Version {
                        major: parts[0].parse().unwrap_or(0),
                        minor: parts[1].parse().unwrap_or(0),
                        patch: parts.get(2).and_then(|p| p.parse().ok()).unwrap_or(0),
                    }
                } else {
                    Version { major: 0, minor: 0, patch: 0 }
                }
            } else {
                let parts: Vec<&str> = s.split('.').collect();
                if parts.len() == 3 {
                    Version {
                        major: parts[0].parse().unwrap_or(0),
                        minor: parts[1].parse().unwrap_or(0),
                        patch: parts[2].parse().unwrap_or(0),
                    }
                } else {
                    Version { major: 0, minor: 0, patch: 0 }
                }
            }
        } else {
            Version { major: 0, minor: 0, patch: 0 }
        };

        let mut all_data = Vec::new();
        let mut page = 0u8;
        loop {
            apdu.clear();
            apdu.push(0x00);
            apdu.push(INS_READ_CONFIG);
            apdu.push(page);
            apdu.push(0x00);
            apdu.push(0x00);

            let rapdu = card.transmit(&apdu, buf)?;
            if rapdu.len() < 2 {
                break;
            }
            let sw = ((rapdu[rapdu.len() - 2] as u16) << 8) | (rapdu[rapdu.len() - 1] as u16);
            let data = if sw == SW_SUCCESS {
                rapdu[..rapdu.len() - 2].to_vec()
            } else if (sw >> 8) == 0x61 {
                let mut result = rapdu[..rapdu.len() - 2].to_vec();
                loop {
                    let get_data: [u8; 5] = [0x00, INS_SEND_REMAINING, 0x00, 0x00, 0x00];
                    let rapdu = card.transmit(&get_data, buf)?;
                    if rapdu.len() < 2 {
                        break;
                    }
                    let sw = ((rapdu[rapdu.len() - 2] as u16) << 8) | (rapdu[rapdu.len() - 1] as u16);
                    result.extend_from_slice(&rapdu[..rapdu.len() - 2]);
                    if sw == SW_SUCCESS || (sw >> 8) != 0x61 {
                        break;
                    }
                }
                result
            } else {
                break;
            };

            if data.is_empty() {
                break;
            }

            let len = data[0] as usize;
            if len == 0 || len >= data.len() {
                break;
            }
            all_data.extend_from_slice(&data[1..=len]);

            let inner_tlvs = parse_tlvs(&data[1..=len]);
            let has_more = inner_tlvs.iter().any(|(tag, val)| *tag == 0x10 && val.first() == Some(&1));
            if !has_more {
                break;
            }
            page += 1;
            if page > 4 {
                break;
            }
        }

        if all_data.is_empty() {
            return Err(Error::Parse("No config data from management app".into()));
        }

        let mut serial = 0;
        let mut form_factor: u8 = 0;
        let mut usb_enabled: u16 = 0;
        let mut nfc_enabled: u16 = 0;

        let tlvs = parse_tlvs(&all_data);
        for (tag, value) in tlvs {
            match tag {
                TAG_SERIAL if value.len() >= 4 => {
                    serial = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
                }
                0x05 if value.len() == 3 => {
                    fw_version = Version {
                        major: value[0],
                        minor: value[1],
                        patch: value[2],
                    };
                }
                TAG_FORM_FACTOR if !value.is_empty() => {
                    form_factor = value[0];
                }
                TAG_USB_ENABLED if !value.is_empty() => {
                    usb_enabled = if value.len() >= 2 {
                        u16::from_be_bytes([value[0], value[1]])
                    } else {
                        value[0] as u16
                    };
                }
                TAG_NFC_ENABLED if value.len() >= 2 => {
                    nfc_enabled = u16::from_be_bytes([value[0], value[1]]);
                }
                _ => {}
            }
        }

        let device_type = match_form_factor(form_factor, fw_version.major);
        let interfaces = format_usb_interfaces(usb_enabled);

        Ok(DeviceInfo {
            device_type,
            serial,
            firmware_version: fw_version,
            usb_enabled: usb_enabled != 0,
            nfc_enabled: nfc_enabled != 0,
            interfaces,
        })
    }

    fn query_otp(card: &mut Card, buf: &mut [u8]) -> Result<Self> {
        let mut apdu = Vec::new();
        apdu.push(0x00);
        apdu.push(0xA4);
        apdu.push(0x04);
        apdu.push(0x00);
        apdu.push(OTP_AID.len() as u8);
        apdu.extend_from_slice(OTP_AID);
        apdu.push(0x00);

        let rapdu = card.transmit(&apdu, buf)?;
        if rapdu.len() < 5 {
            return Err(Error::Parse("OTP SELECT response too short".into()));
        }
        let sw = ((rapdu[rapdu.len() - 2] as u16) << 8) | (rapdu[rapdu.len() - 1] as u16);
        if sw != SW_SUCCESS {
            return Err(Error::Parse("OTP app not available".into()));
        }

        let fw_version = if rapdu.len() >= 3 {
            Version {
                major: rapdu[0],
                minor: rapdu[1],
                patch: rapdu[2],
            }
        } else {
            Version { major: 0, minor: 0, patch: 0 }
        };

        let mut all_data = Vec::new();
        for page in 0..2u8 {
            apdu.clear();
            apdu.push(0x00);
            apdu.push(INS_READ_CONFIG);
            apdu.push(page);
            apdu.push(0x00);
            apdu.push(0x00);

            let rapdu = card.transmit(&apdu, buf)?;
            if rapdu.len() < 2 {
                continue;
            }
            let sw = ((rapdu[rapdu.len() - 2] as u16) << 8) | (rapdu[rapdu.len() - 1] as u16);
            if sw != SW_SUCCESS {
                if page == 0 {
                    return Err(Error::Parse(format!("OTP config read failed: 0x{:04X}", sw)));
                }
                continue;
            }

            let data = &rapdu[..rapdu.len() - 2];
            if data.is_empty() || data[0] as usize >= data.len() {
                if page == 0 {
                    return Err(Error::Parse(format!("Invalid config response ({} bytes)", data.len())));
                }
                continue;
            }
            let len = data[0] as usize;
            all_data.extend_from_slice(&data[1..=len]);
        }

        if all_data.is_empty() {
            return Err(Error::Parse("No config data from OTP app".into()));
        }

        let mut serial = 0;
        let mut usb_enabled: u16 = 0;
        let mut form_factor: u8 = 0;
        let mut fw_version = fw_version;

        let tlvs = parse_tlvs(&all_data);
        for (tag, value) in tlvs {
            match tag {
                TAG_SERIAL if value.len() >= 4 => {
                    let start = value.len().saturating_sub(4);
                    serial = u32::from_be_bytes([
                        value[start],
                        value[start + 1],
                        value[start + 2],
                        value[start + 3],
                    ]);
                }
                0x05 if value.len() == 3 => {
                    fw_version = Version {
                        major: value[0],
                        minor: value[1],
                        patch: value[2],
                    };
                }
                TAG_USB_ENABLED if !value.is_empty() => {
                    usb_enabled = if value.len() >= 2 {
                        u16::from_be_bytes([value[0], value[1]])
                    } else {
                        value[0] as u16
                    };
                }
                TAG_FORM_FACTOR if !value.is_empty() => {
                    form_factor = value[0];
                }
                _ => {}
            }
        }

        let device_type = match_form_factor(form_factor, fw_version.major);
        let interfaces = format_usb_interfaces(usb_enabled);

        Ok(DeviceInfo {
            device_type,
            serial,
            firmware_version: fw_version,
            usb_enabled: usb_enabled != 0,
            nfc_enabled: false,
            interfaces,
        })
    }
}

fn match_form_factor(code: u8, major: u8) -> String {
    if major < 5 {
        return "YubiKey 4".to_string();
    }
    match code & 0x0F {
        0x00 => "YubiKey".to_string(),
        0x01 => "YubiKey Keychain (USB-A)".to_string(),
        0x02 => "YubiKey Nano (USB-A)".to_string(),
        0x03 => "YubiKey Keychain (USB-C)".to_string(),
        0x04 => "YubiKey Nano (USB-C)".to_string(),
        0x05 => "YubiKey 5Ci".to_string(),
        0x06 => "YubiKey Bio (USB-A)".to_string(),
        0x07 => "YubiKey Bio (USB-C)".to_string(),
        _ => "YubiKey".to_string(),
    }
}

fn format_usb_interfaces(enabled: u16) -> String {
    let mut ifaces = Vec::new();
    if enabled & CAP_OTP != 0 {
        ifaces.push("OTP");
    }
    if enabled & (CAP_U2F | CAP_FIDO2) != 0 {
        ifaces.push("FIDO");
    }
    if enabled & (CAP_OATH | CAP_PIV | CAP_OPENPGP | CAP_HSMAUTH) != 0 {
        ifaces.push("CCID");
    }
    if ifaces.is_empty() {
        "None".to_string()
    } else {
        ifaces.join(", ")
    }
}

#[derive(Debug)]
pub enum Error {
    Pcsc(pcsc::Error),
    Apdu { sw: u16, msg: String },
    Parse(String),
    NoReaders,
    NoCard,
    MultipleDevices,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Pcsc(e) => write!(f, "PC/SC error: {}", e),
            Error::Apdu { sw, msg } => write!(f, "APDU error 0x{:04X}: {}", sw, msg),
            Error::Parse(e) => write!(f, "Parse error: {}", e),
            Error::NoReaders => write!(f, "Device is not available"),
            Error::NoCard => write!(f, "Device is not available"),
            Error::MultipleDevices => write!(f, "Multiple devices detected, aborting for safety"),
        }
    }
}

impl From<pcsc::Error> for Error {
    fn from(e: pcsc::Error) -> Self {
        Error::Pcsc(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

pub struct OathSession {
    card: Card,
    version: Version,
    salt: Vec<u8>,
    challenge: Option<Vec<u8>>,
    device_id: String,
}

fn concat_tlvs(chunks: &[Vec<u8>]) -> Vec<u8> {
    let total_len: usize = chunks.iter().map(|c| c.len()).sum();
    let mut result = Vec::with_capacity(total_len);
    for chunk in chunks {
        result.extend_from_slice(chunk);
    }
    result
}

impl OathSession {
    pub fn connect() -> Result<Self> {
        let ctx = Context::establish(Scope::User).map_err(Error::from)?;
        let mut readers_buf = [0; 2048];
        let readers = ctx.list_readers(&mut readers_buf).map_err(Error::from)?;

        let reader_count = readers.clone().count();
        if reader_count == 0 {
            return Err(Error::NoReaders);
        }
        if reader_count > 1 {
            return Err(Error::MultipleDevices);
        }

        let reader_name = readers.last().ok_or(Error::NoReaders)?;
        let card = ctx
            .connect(reader_name, ShareMode::Shared, Protocols::ANY)
            .map_err(|e| {
                if let pcsc::Error::NoSmartcard = e {
                    Error::NoCard
                } else {
                    Error::Pcsc(e)
                }
            })?;

        let mut session = Self {
            card,
            version: Version {
                major: 0,
                minor: 0,
                patch: 0,
            },
            salt: Vec::new(),
            challenge: None,
            device_id: String::new(),
        };

        session.select()?;
        Ok(session)
    }

    pub fn card(&mut self) -> &mut Card {
        &mut self.card
    }

    fn transmit(&mut self, apdu: &[u8]) -> Result<Vec<u8>> {
        let mut rapdu_buf = [0; MAX_BUFFER_SIZE_EXTENDED];
        let rapdu = self.card.transmit(apdu, &mut rapdu_buf)?;

        if rapdu.len() < 2 {
            return Err(Error::Parse("Response too short".into()));
        }

        let sw = ((rapdu[rapdu.len() - 2] as u16) << 8) | (rapdu[rapdu.len() - 1] as u16);
        let data = &rapdu[..rapdu.len() - 2];

        if sw == SW_SUCCESS {
            Ok(data.to_vec())
        } else if (sw >> 8) == 0x61 {
            let mut result = data.to_vec();
            loop {
                let get_data = [0x00, INS_SEND_REMAINING, 0x00, 0x00, 0x00];
                let rapdu = self.card.transmit(&get_data, &mut rapdu_buf)?;
                if rapdu.len() < 2 {
                    return Err(Error::Parse("Response too short".into()));
                }
                let sw = ((rapdu[rapdu.len() - 2] as u16) << 8) | (rapdu[rapdu.len() - 1] as u16);
                let chunk = &rapdu[..rapdu.len() - 2];
                result.extend_from_slice(chunk);
                if sw == SW_SUCCESS {
                    break;
                } else if (sw >> 8) != 0x61 {
                    return Err(Error::Apdu {
                        sw,
                        msg: "Failed to get remaining data".into(),
                    });
                }
            }
            Ok(result)
        } else {
            Err(Error::Apdu {
                sw,
                msg: format!("APDU failed with status 0x{:04X}", sw),
            })
        }
    }

    fn send_apdu(&mut self, cla: u8, ins: u8, p1: u8, p2: u8, data: Option<&[u8]>) -> Result<Vec<u8>> {
        let mut apdu = Vec::new();
        apdu.push(cla);
        apdu.push(ins);
        apdu.push(p1);
        apdu.push(p2);

        if let Some(d) = data {
            apdu.push(d.len() as u8);
            apdu.extend_from_slice(d);
        }

        apdu.push(0x00);

        self.transmit(&apdu)
    }

    fn select(&mut self) -> Result<()> {
        let mut apdu = Vec::new();
        apdu.push(0x00);
        apdu.push(0xA4);
        apdu.push(0x04);
        apdu.push(0x00);
        apdu.push(YUBICO_OATH_AID.len() as u8);
        apdu.extend_from_slice(YUBICO_OATH_AID);
        apdu.push(0x00);

        let response = self.transmit(&apdu)?;
        let tlvs = parse_tlvs(&response);

        let mut version = None;
        let mut salt = None;
        let mut challenge = None;

        for (tag, value) in tlvs {
            match tag {
                TAG_VERSION => version = Version::from_bytes(value),
                TAG_NAME => salt = Some(value.to_vec()),
                TAG_CHALLENGE => challenge = Some(value.to_vec()),
                _ => {}
            }
        }

        self.version = version.ok_or_else(|| Error::Parse("Missing version in SELECT response".into()))?;
        self.salt = salt.ok_or_else(|| Error::Parse("Missing salt in SELECT response".into()))?;
        self.challenge = challenge;
        self.device_id = get_device_id(&self.salt);

        Ok(())
    }

    #[allow(dead_code)]
    pub fn version(&self) -> &Version {
        &self.version
    }

    #[allow(dead_code)]
    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    pub fn has_key(&self) -> bool {
        self.challenge.is_some()
    }

    pub fn locked(&self) -> bool {
        self.challenge.is_some()
    }

    pub fn derive_key(&self, password: &str) -> Vec<u8> {
        derive_key(&self.salt, password)
    }

    pub fn validate(&mut self, key: &[u8]) -> Result<()> {
        let challenge = self.challenge.as_ref().ok_or(Error::Parse("No challenge available".into()))?;
        let response = hmac_sha1(key, challenge);

        let mut client_challenge = [0u8; 8];
        getrandom::getrandom(&mut client_challenge).map_err(|_| Error::Parse("Failed to generate random".into()))?;

        let data = concat_tlvs(&[
            tlv(TAG_RESPONSE, &response),
            tlv(TAG_CHALLENGE, &client_challenge),
        ]);
        let resp = self.send_apdu(0x00, INS_VALIDATE, 0x00, 0x00, Some(&data))?;

        let tlvs = parse_tlvs(&resp);
        for (tag, value) in tlvs {
            if tag == TAG_RESPONSE {
                let expected = hmac_sha1(key, &client_challenge);
                if value != expected {
                    return Err(Error::Apdu {
                        sw: SW_INCORRECT_PARAMS,
                        msg: "Server response does not match verification".into(),
                    });
                }
            }
        }

        self.challenge = None;
        Ok(())
    }

    pub fn set_key(&mut self, key: &[u8]) -> Result<()> {
        let mut client_challenge = [0u8; 8];
        getrandom::getrandom(&mut client_challenge).map_err(|_| Error::Parse("Failed to generate random".into()))?;

        let response = hmac_sha1(key, &client_challenge);

        let key_data = {
            let mut k = vec![(OathType::Totp as u8) | (Algorithm::Sha1 as u8)];
            k.extend_from_slice(key);
            k
        };

        let data = concat_tlvs(&[
            tlv(TAG_KEY, &key_data),
            tlv(TAG_CHALLENGE, &client_challenge),
            tlv(TAG_RESPONSE, &response),
        ]);

        self.send_apdu(0x00, INS_SET_CODE, 0x00, 0x00, Some(&data))?;
        self.challenge = Some(client_challenge.to_vec());
        Ok(())
    }

    pub fn unset_key(&mut self) -> Result<()> {
        let data = tlv(TAG_KEY, &[]);
        self.send_apdu(0x00, INS_SET_CODE, 0x00, 0x00, Some(&data))?;
        self.challenge = None;
        Ok(())
    }

    pub fn reset(&mut self) -> Result<()> {
        self.send_apdu(0x00, INS_RESET, 0xDE, 0xAD, None)?;
        self.select()?;
        Ok(())
    }

    pub fn list_credentials(&mut self) -> Result<Vec<Credential>> {
        let resp = self.send_apdu(0x00, INS_LIST, 0x00, 0x00, None)?;
        let mut credentials = Vec::new();

        for (tag, value) in parse_tlvs(&resp) {
            if tag == TAG_NAME_LIST && value.len() >= 1 {
                let oath_type = OathType::from_u8(value[0])
                    .ok_or_else(|| Error::Parse(format!("Unknown OATH type: 0x{:02X}", value[0])))?;
                let cred_id = &value[1..];
                let (issuer, name, period) = parse_cred_id(cred_id, oath_type);

                credentials.push(Credential {
                    id: cred_id.to_vec(),
                    issuer,
                    name,
                    oath_type,
                    period,
                    digits: 6,
                    algorithm: Algorithm::Sha1,
                    touch_required: false,
                });
            }
        }

        Ok(credentials)
    }

    pub fn put_credential(
        &mut self,
        name: &str,
        secret: &[u8],
        oath_type: OathType,
        algorithm: Algorithm,
        digits: u8,
        period: u32,
        counter: Option<u32>,
        issuer: Option<&str>,
        touch_required: bool,
    ) -> Result<()> {
        let cred_id = format_cred_id(issuer, name, oath_type, period);

        let shortened_secret = hmac_shorten_key(secret, algorithm);
        let mut padded_secret = shortened_secret;
        while padded_secret.len() < HMAC_MINIMUM_KEY_SIZE {
            padded_secret.push(0);
        }

        let mut data = tlv(TAG_NAME, &cred_id);

        let mut key_value = vec![(oath_type as u8) | (algorithm as u8), digits];
        key_value.extend_from_slice(&padded_secret);
        data.extend_from_slice(&tlv(TAG_KEY, &key_value));

        if touch_required {
            data.extend_from_slice(&tlv(TAG_PROPERTY, &[0x02]));
        }

        if let Some(c) = counter {
            if c > 0 {
                data.extend_from_slice(&tlv(TAG_IMF, &c.to_be_bytes()));
            }
        }

        self.send_apdu(0x00, INS_PUT, 0x00, 0x00, Some(&data))?;
        Ok(())
    }

    pub fn delete_credential(&mut self, cred_id: &[u8]) -> Result<()> {
        let data = tlv(TAG_NAME, cred_id);
        self.send_apdu(0x00, INS_DELETE, 0x00, 0x00, Some(&data))?;
        Ok(())
    }

    pub fn calculate_code(&mut self, cred_id: &[u8], challenge: &[u8]) -> Result<Vec<u8>> {
        let data = concat_tlvs(&[
            tlv(TAG_NAME, cred_id),
            tlv(TAG_CHALLENGE, challenge),
        ]);
        let resp = self.send_apdu(0x00, INS_CALCULATE, 0x00, 0x01, Some(&data))?;

        for (tag, value) in parse_tlvs(&resp) {
            if tag == TAG_TRUNCATED {
                return Ok(value.to_vec());
            }
        }

        Err(Error::Parse("No truncated response found".into()))
    }

    pub fn calculate_all(&mut self) -> Result<Vec<(Credential, Option<Code>)>> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let challenge = get_challenge(timestamp, 30);
        let data = tlv(TAG_CHALLENGE, &challenge);
        let resp = self.send_apdu(0x00, INS_CALCULATE_ALL, 0x00, 0x01, Some(&data))?;

        let mut entries = Vec::new();
        let tlvs = parse_tlvs(&resp);
        let mut i = 0;

        while i + 1 < tlvs.len() {
            let (tag1, value1) = tlvs[i];
            let (tag2, value2) = tlvs[i + 1];
            i += 2;

            if tag1 == TAG_NAME {
                let cred_id = value1;
                let oath_type = if tag2 == TAG_HOTP {
                    OathType::Hotp
                } else if tag2 == TAG_TOUCH {
                    OathType::Totp
                } else {
                    OathType::Totp
                };

                let (issuer, name, period) = parse_cred_id(cred_id, oath_type);
                let touch = tag2 == TAG_TOUCH;

                let credential = Credential {
                    id: cred_id.to_vec(),
                    issuer,
                    name,
                    oath_type,
                    period,
                    digits: 6,
                    algorithm: Algorithm::Sha1,
                    touch_required: touch,
                };

                let code = if tag2 == TAG_TRUNCATED && value2.len() >= 5 {
                    let value = format_code_from_truncated(value2);
                    Some(Code {
                        value,
                        valid_from: (timestamp / 30) * 30,
                        valid_to: ((timestamp / 30) + 1) * 30,
                    })
                } else {
                    None
                };

                entries.push((credential, code));
            }
        }

        Ok(entries)
    }

    pub fn get_code(&mut self, credential: &Credential, timestamp: Option<u64>) -> Result<Code> {
        let timestamp = timestamp.unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
        });

        let challenge = if credential.oath_type == OathType::Totp {
            get_challenge(timestamp, credential.period)
        } else {
            vec![]
        };

        let resp = self.calculate_code(&credential.id, &challenge)?;

        if resp.len() < 5 {
            return Err(Error::Parse("Response too short".into()));
        }

        let value = format_code_from_truncated(&resp);
        let (valid_from, valid_to) = if credential.oath_type == OathType::Totp {
            let time_step = timestamp / credential.period as u64;
            (time_step * credential.period as u64, (time_step + 1) * credential.period as u64)
        } else {
            (timestamp, u64::MAX)
        };

        Ok(Code {
            value,
            valid_from,
            valid_to,
        })
    }
}
