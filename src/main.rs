mod oath;
mod session;
mod usb_ccid;

use clap::{Parser, Subcommand};
use data_encoding::BASE32;
use std::io::{self, Write};

use oath::{Algorithm, OathType};
use session::OathSession;

#[derive(Parser)]
#[command(name = "yubicli", version, about = "YubiKey OATH CLI tool", long_about = None)]
struct Cli {
    /// Password to unlock
    #[arg(short = 'p', long)]
    password: Option<String>,
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// List all OATH accounts
    List {
        /// Show OATH type
        #[arg(short = 'o', long)]
        show_type: bool,
        /// Show period
        #[arg(short = 'P', long)]
        show_period: bool,
        /// Password to unlock
        #[arg(short = 'p', long)]
        password: Option<String>,
    },
    /// Generate codes for accounts
    Code {
        /// Query to match accounts
        query: Option<String>,
        /// Ensure single match, output only code
        #[arg(short = 's', long)]
        single: bool,
        /// Show hidden accounts
        #[arg(short = 'H', long)]
        show_hidden: bool,
        /// Password to unlock
        #[arg(short = 'p', long)]
        password: Option<String>,
    },
    /// Add a new account
    Add {
        /// Account name
        name: String,
        /// Base32-encoded secret key
        secret: Option<String>,
        /// OATH type (totp or hotp)
        #[arg(short = 'o', long, default_value = "totp")]
        oath_type: String,
        /// Number of digits
        #[arg(short = 'd', long, default_value = "6")]
        digits: u8,
        /// Hash algorithm
        #[arg(short = 'a', long, default_value = "sha1")]
        algorithm: String,
        /// Initial counter for HOTP
        #[arg(short = 'c', long)]
        counter: Option<u32>,
        /// Issuer name
        #[arg(short = 'i', long)]
        issuer: Option<String>,
        /// TOTP period in seconds
        #[arg(short = 'P', long, default_value = "30")]
        period: u32,
        /// Require touch
        #[arg(short = 't', long)]
        touch: bool,
        /// Password to unlock
        #[arg(short = 'p', long)]
        password: Option<String>,
    },
    /// Delete an account
    Delete {
        /// Query to match account
        query: String,
        /// Password to unlock
        #[arg(short = 'p', long)]
        password: Option<String>,
    },
    /// Manage password protection
    #[command(subcommand)]
    Access(AccessCommands),
    /// Show OATH application info
    Info {},
    /// Reset OATH application (deletes all accounts)
    Reset {
        /// Skip confirmation
        #[arg(short = 'f', long)]
        force: bool,
    },
}

#[derive(Subcommand)]
enum AccessCommands {
    /// Set a new password (when none is set)
    Set {
        /// New password (will prompt if not provided)
        #[arg(short = 'p', long)]
        password: Option<String>,
    },
    /// Change the current password
    Change {
        /// Current password (will prompt if not provided)
        #[arg(short = 'c', long)]
        current: Option<String>,
        /// New password (will prompt if not provided)
        #[arg(short = 'n', long)]
        new_password: Option<String>,
    },
    /// Clear/disable password protection
    Clear {
        /// Current password (will prompt if not provided)
        #[arg(short = 'p', long)]
        password: Option<String>,
    },
}

fn main() {
    #[cfg(target_os = "linux")]
    {
        use std::env;
        let args: Vec<String> = env::args().collect();
        if args.len() == 3 && args[1] == "__clipboard_daemon__" {
            clipboard_daemon(&args[2]);
            return;
        }
    }

    let cli = Cli::parse();

    let result = match cli.command {
        None => cmd_code(None, false, false, cli.password),
        Some(Commands::List {
            show_type,
            show_period,
            password,
        }) => cmd_list(show_type, show_period, password),
        Some(Commands::Code {
            query,
            single,
            show_hidden,
            password,
        }) => cmd_code(query, single, show_hidden, password),
        Some(Commands::Add {
            name,
            secret,
            oath_type,
            digits,
            algorithm,
            counter,
            issuer,
            period,
            touch,
            password,
        }) => cmd_add(name, secret, oath_type, digits, algorithm, counter, issuer, period, touch, password),
        Some(Commands::Delete { query, password }) => cmd_delete(query, password),
        Some(Commands::Access(access)) => cmd_access(access),
        Some(Commands::Info {}) => cmd_info(),
        Some(Commands::Reset { force }) => cmd_reset(force),
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

fn cmd_info() -> session::Result<()> {
    let mut session = OathSession::connect()?;

    match session::DeviceInfo::query(session.device()) {
        Ok(info) => {
            println!("Device type: {}", info.device_type);
            println!("Serial number: {}", info.serial);
            println!("Firmware version: {}", info.firmware_version);
            println!("Enabled USB interfaces: {}", info.interfaces);
        }
        Err(e) => {
            eprintln!("Warning: Could not query device info: {}", e);
        }
    }

    println!(
        "Password protection: {}",
        if session.has_key() { "enabled" } else { "disabled" }
    );
    Ok(())
}

fn cmd_list(show_type: bool, show_period: bool, password: Option<String>) -> session::Result<()> {
    let mut session = OathSession::connect()?;
    unlock(&mut session, &password)?;

    let creds = session.list_credentials()?;
    for cred in creds {
        if cred.name.starts_with('_') && cred.issuer.as_deref() == Some("_hidden") {
            continue;
        }
        print!("{}", cred.name);
        if let Some(issuer) = &cred.issuer {
            print!(" ({})", issuer);
        }
        if show_type {
            print!(", {}", match cred.oath_type {
                OathType::Totp => "TOTP",
                OathType::Hotp => "HOTP",
            });
        }
        if show_period && cred.oath_type == OathType::Totp {
            print!(", {}s", cred.period);
        }
        println!();
    }
    Ok(())
}

fn cmd_code(
    query: Option<String>,
    single: bool,
    show_hidden: bool,
    password: Option<String>,
) -> session::Result<()> {
    let mut session = OathSession::connect()?;
    unlock(&mut session, &password)?;

    let entries = session.calculate_all()?;

    let mut matches: Vec<_> = entries
        .into_iter()
        .filter(|(cred, _)| {
            if !show_hidden {
                if let Some(issuer) = &cred.issuer {
                    if issuer == "_hidden" {
                        return false;
                    }
                }
            }
            true
        })
        .filter(|(cred, _)| {
            if let Some(q) = &query {
                let full_name = if let Some(issuer) = &cred.issuer {
                    format!("{}:{}", issuer, cred.name)
                } else {
                    cred.name.clone()
                };
                full_name.to_lowercase().contains(&q.to_lowercase())
            } else {
                true
            }
        })
        .collect();

    if single {
        if matches.len() == 1 {
            let (cred, mut code) = matches.pop().unwrap();
            if code.is_none() {
                code = Some(session.get_code(&cred, None)?);
            }
            if let Some(code) = code {
                println!("{}", code.value);
                copy_to_clipboard(&code.value);
            } else if cred.touch_required {
                eprintln!("[Requires Touch]");
            } else {
                eprintln!("[HOTP Account]");
            }
        } else if matches.is_empty() {
            eprintln!("No matching account found.");
            std::process::exit(1);
        } else {
            eprintln!("Multiple matches, make the query more specific.");
            eprintln!();
            for (cred, _) in &matches {
                eprintln!("{}", cred.name);
            }
            std::process::exit(1);
        }
    } else if matches.len() == 1 {
        let (cred, mut code) = matches.pop().unwrap();
        if code.is_none() {
            code = Some(session.get_code(&cred, None)?);
        }
        let name = if let Some(issuer) = &cred.issuer {
            format!("{}:{}", issuer, cred.name)
        } else {
            cred.name.clone()
        };
        if let Some(code) = &code {
            println!("{}  {}", name, code.value);
            copy_to_clipboard(&code.value);
        } else if cred.touch_required {
            println!("{}  [Requires Touch]", name);
        } else {
            println!("{}  [HOTP Account]", name);
        }
    } else {
        let mut outputs: Vec<(String, String)> = Vec::new();
        for (cred, code) in &matches {
            let name = if let Some(issuer) = &cred.issuer {
                format!("{}:{}", issuer, cred.name)
            } else {
                cred.name.clone()
            };
            let value = if let Some(code) = code {
                code.value.clone()
            } else if cred.touch_required {
                "[Requires Touch]".to_string()
            } else if cred.oath_type == OathType::Hotp {
                "[HOTP Account]".to_string()
            } else {
                String::new()
            };
            outputs.push((name, value));
        }

        let max_name_len = outputs.iter().map(|(n, _)| n.len()).max().unwrap_or(0);
        let max_code_len = outputs.iter().map(|(_, c)| c.len()).max().unwrap_or(0);

        for (name, code) in &outputs {
            println!("{:<width_name$}  {:>width_code$}", name, code, width_name = max_name_len, width_code = max_code_len);
        }
    }
    Ok(())
}

fn copy_to_clipboard(text: &str) {
    use arboard::Clipboard;

    if let Ok(mut clipboard) = Clipboard::new() {
        let _ = clipboard.set_text(text);
    }

    #[cfg(all(target_os = "linux"))]
    {
        use std::env;
        use std::process::{Command, Stdio};

        if env::var("WAYLAND_DISPLAY").is_err() && env::var("DISPLAY").is_ok() {
            let exe = env::current_exe().ok();
            if let Some(exe) = exe {
                let _ = Command::new(exe)
                    .arg("__clipboard_daemon__")
                    .arg(text)
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn();
            }
        }
    }
}

fn cmd_add(
    name: String,
    secret: Option<String>,
    oath_type_str: String,
    digits: u8,
    algorithm_str: String,
    counter: Option<u32>,
    issuer: Option<String>,
    period: u32,
    touch: bool,
    password: Option<String>,
) -> session::Result<()> {
    let secret = if let Some(s) = secret {
        parse_b32_key(&s)?
    } else {
        print!("Enter a secret key (base32): ");
        io::stdout().flush().unwrap();
        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        parse_b32_key(input.trim())?
    };

    let oath_type = match oath_type_str.to_lowercase().as_str() {
        "totp" => OathType::Totp,
        "hotp" => OathType::Hotp,
        _ => {
            eprintln!("Invalid OATH type. Use 'totp' or 'hotp'.");
            std::process::exit(1);
        }
    };

    let algorithm = match algorithm_str.to_lowercase().as_str() {
        "sha1" => Algorithm::Sha1,
        "sha256" => Algorithm::Sha256,
        "sha512" => Algorithm::Sha512,
        _ => {
            eprintln!("Invalid algorithm. Use 'sha1', 'sha256', or 'sha512'.");
            std::process::exit(1);
        }
    };

    let mut session = OathSession::connect()?;
    unlock(&mut session, &password)?;

    session.put_credential(
        &name,
        &secret,
        oath_type,
        algorithm,
        digits,
        period,
        counter,
        issuer.as_deref(),
        touch,
    )?;

    println!("Account added.");
    Ok(())
}

fn cmd_delete(query: String, password: Option<String>) -> session::Result<()> {
    let mut session = OathSession::connect()?;
    unlock(&mut session, &password)?;

    let creds = session.list_credentials()?;
    let matches: Vec<_> = creds
        .iter()
        .filter(|cred| {
            let full_name = if let Some(issuer) = &cred.issuer {
                format!("{}:{}", issuer, cred.name)
            } else {
                cred.name.clone()
            };
            full_name.to_lowercase().contains(&query.to_lowercase())
        })
        .collect();

    if matches.is_empty() {
        println!("No matches, nothing to be done.");
    } else if matches.len() == 1 {
        let cred = matches[0];
        print!("Delete account: {}? [y/N] ", cred.name);
        io::stdout().flush().unwrap();
        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        if input.trim().to_lowercase() == "y" {
            session.delete_credential(&cred.id)?;
            println!("Deleted {}.", cred.name);
        } else {
            println!("Deletion aborted by user.");
        }
    } else {
        eprintln!("Multiple matches, make the query more specific.");
        eprintln!();
        for cred in &matches {
            eprintln!("{}", cred.name);
        }
        std::process::exit(1);
    }
    Ok(())
}

fn cmd_access(access: AccessCommands) -> session::Result<()> {
    let mut session = OathSession::connect()?;

    match access {
        AccessCommands::Set { password } => {
            if session.has_key() {
                eprintln!("A password is already set. Use 'access change' to modify it.");
                std::process::exit(1);
            }
            let new_pass = if let Some(p) = password {
                p
            } else {
                read_password_twice("Enter new password: ", "Confirm new password: ")
            };

            let key = session.derive_key(&new_pass);
            session.set_key(&key)?;
            println!("Password set.");
        }
        AccessCommands::Change { current, new_password } => {
            if !session.has_key() {
                eprintln!("No password is set. Use 'access set' to create one.");
                std::process::exit(1);
            }

            let current_pass = if let Some(p) = current {
                p
            } else {
                read_password("Enter current password: ")
            };

            let key = session.derive_key(&current_pass);
            if let Err(_) = session.validate(&key) {
                eprintln!("None shall pass.");
                std::process::exit(1);
            }

            let new_pass = if let Some(p) = new_password {
                p
            } else {
                read_password_twice("Enter new password", "Confirm new password")
            };

            let key = session.derive_key(&new_pass);
            session.set_key(&key)?;
            println!("Password changed.");
        }
        AccessCommands::Clear { password } => {
            if !session.has_key() {
                eprintln!("No password is set.");
                std::process::exit(1);
            }

            let current_pass = if let Some(p) = password {
                p
            } else {
                read_password("Enter current password: ")
            };

            let key = session.derive_key(&current_pass);
            if let Err(_) = session.validate(&key) {
                eprintln!("None shall pass.");
                std::process::exit(1);
            }
            session.unset_key()?;
            println!("Password cleared.");
        }
    }
    Ok(())
}

fn cmd_reset(force: bool) -> session::Result<()> {
    if !force {
        print!("WARNING! This will delete all accounts. Proceed? [y/N] ");
        io::stdout().flush().unwrap();
        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        if input.trim().to_lowercase() != "y" {
            println!("Reset aborted.");
            return Ok(());
        }
    }

    let mut session = OathSession::connect()?;
    println!("Resetting data...");
    session.reset()?;
    println!("Reset complete. All accounts have been deleted.");
    Ok(())
}

fn unlock(session: &mut OathSession, password: &Option<String>) -> session::Result<()> {
    if session.locked() {
        let key = if let Some(p) = password {
            session.derive_key(p)
        } else {
            let input = read_password("Enter password: ");
            session.derive_key(&input)
        };
        if let Err(_) = session.validate(&key) {
            eprintln!("None shall pass.");
            std::process::exit(1);
        }
    } else if password.is_some() {
        eprintln!("Password provided, but no password is set.");
        std::process::exit(1);
    }
    Ok(())
}

fn read_password(prompt: &str) -> String {
    rpassword::prompt_password(prompt).unwrap_or_default()
}

fn read_password_twice(prompt1: &str, prompt2: &str) -> String {
    let p1 = read_password(prompt1);
    let p2 = read_password(prompt2);
    if p1 != p2 {
        eprintln!("Passwords do not match.");
        std::process::exit(1);
    }
    if p1.is_empty() {
        eprintln!("Password cannot be empty.");
        std::process::exit(1);
    }
    p1
}

fn parse_b32_key(key: &str) -> session::Result<Vec<u8>> {
    let key = key.to_uppercase().replace(' ', "");
    let padded = if key.len() % 8 != 0 {
        format!("{}{}", key, "=".repeat(8 - key.len() % 8))
    } else {
        key
    };
    BASE32
        .decode(padded.as_bytes())
        .map_err(|e| session::Error::Parse(format!("Invalid base32 key: {}", e)))
}

#[cfg(target_os = "linux")]
fn clipboard_daemon(text: &str) {
    use arboard::Clipboard;
    use std::thread;
    use std::time::Duration;

    if let Ok(mut clipboard) = Clipboard::new() {
        let _ = clipboard.set_text(text);
        thread::sleep(Duration::from_secs(5));
    }
}
