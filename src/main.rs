extern crate pcsc;
extern crate clipboard;
extern crate rpassword;
extern crate data_encoding;
use data_encoding::BASE32;
use data_encoding::BASE64;
use rpassword::read_password;
use std::io::Write;
use pcsc::*;
use clipboard::ClipboardProvider;
use clipboard::ClipboardContext;
use std::os::raw::{c_uint};

// TLV tags for credential data
pub const TAG_NAME: c_uint = 0x71;
pub const TAG_NAME_LIST: c_uint = 0x72;
pub const TAG_KEY: c_uint = 0x73;
pub const TAG_CHALLENGE: c_uint = 0x74;
pub const TAG_RESPONSE: c_uint = 0x75;
pub const TAG_TRUNCATED: c_uint = 0x76;
pub const TAG_HOTP: c_uint = 0x77;
pub const TAG_PROPERTY: c_uint = 0x78;
pub const TAG_VERSION: c_uint = 0x79;
pub const TAG_IMF: c_uint = 0x7A;
pub const TAG_TOUCH: c_uint = 0x7C;

// Instruction bytes for commands
pub const INS_LIST: c_uint = 0xA1;
pub const INS_PUT: c_uint = 0x01;
pub const INS_DELETE: c_uint = 0x02;
pub const INS_SET_CODE: c_uint = 0x03;
pub const INS_RESET: c_uint = 0x04;
pub const INS_RENAME: c_uint = 0x05;
pub const INS_CALCULATE: c_uint = 0xA2;
pub const INS_VALIDATE: c_uint = 0xA3;
pub const INS_CALCULATE_ALL: c_uint = 0xA4;
pub const INS_SEND_REMAINING: c_uint = 0xA5;

//TOTP_ID_PATTERN = re.compile(r"^((\d+)/)?(([^:]+):)?(.+)$")

pub const MASK_ALGO: c_uint = 0x0F;
pub const MASK_TYPE: c_uint = 0xF0;

pub const DEFAULT_PERIOD: usize = 30;
pub const DEFAULT_DIGITS: usize = 6;
pub const DEFAULT_IMF: usize = 0;
pub const CHALLENGE_LEN: usize = 8;
pub const HMAC_MINIMUM_KEY_SIZE: usize = 14;

//class HASH_ALGORITHM(IntEnum):
//    SHA1 = 0x01
//    SHA256 = 0x02
//    SHA512 = 0x03
    
pub const HASH_ALGORITHM: [u8; 3] = [0x01, 0x02, 0x03];

//class OATH_TYPE(IntEnum):
//    HOTP = 0x10
//    TOTP = 0x20

pub const OATH_TYPE: [u8; 2] = [0x010, 0x020];

pub const PROP_REQUIRE_TOUCHL: usize = 0x02;

fn main() {
    // Establish a PC/SC context.
    let ctx = match Context::establish(Scope::User) {
        Ok(ctx) => ctx,
        Err(err) => {
            eprintln!("Failed to establish context: {}", err);
            std::process::exit(1);
        }
    };

    // List available readers.
    let mut readers_buf = [0; 2048];
    let mut readers = match ctx.list_readers(&mut readers_buf) {
        Ok(readers) => readers,
        Err(err) => {
            eprintln!("Failed to list readers: {}", err);
            std::process::exit(1);
        }
    };

    // Use the first reader.
    let reader = match readers.next() {
        Some(reader) => reader,
        None => {
            println!("No readers are connected.");
            return;
        }
    };
    println!("Using reader: {:?}", reader);
    let mut ctx: ClipboardContext = ClipboardProvider::new().unwrap();
    ctx.set_contents(reader.to_str().unwrap().to_owned()).unwrap();
    
    print!("Type a password: ");
    std::io::stdout().flush().unwrap();
    let password = read_password().unwrap();
    println!("The password is: '{}'", password);
   
    let data: Vec<u8> = vec![1,2,3,4,5];
    println!("{}", BASE32.encode(&data));
    println!("{}", BASE64.encode(&data));
}
