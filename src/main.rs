extern crate pcsc;
extern crate clipboard;
extern crate rpassword;
    
use rpassword::read_password;
use std::io::Write;
use pcsc::*;
use clipboard::ClipboardProvider;
use clipboard::ClipboardContext;

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
}
