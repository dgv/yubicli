[<img src="https://raw.githubusercontent.com/iqlusioninc/yubikey.rs/main/img/logo.png" width="150" height="110" alt="ferris">](https://github.com/iqlusioninc/yubikey.rs)

# yubicli

[![Build Status](https://github.com/dgv/yubicli/actions/workflows/build.yml/badge.svg)](https://github.com/dgv/yubicli/actions/workflows/build.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A minimal CLI tool for YubiKey OATH authentication, inspired by [rsc/2fa](https://github.com/rsc/2fa) but designed to work directly with YubiKeys via PC/SC using reverse-engineered specification from [trussed](https://github.com/trussed-dev/oath-authenticator). 

### Motivation

Replace the bloated Yubico Authenticator utilities with a simple, dependency-free binary for managing TOTP/HOTP codes stored on YubiKeys.

### Supported YubiKeys

- YubiKey 4 series
- YubiKey 5 series _(not tested)_

NOTE: Nano and USB-C variants of the above are also supported. NEO series is NOT supported.

### Usage

```
Usage: yubicli [OPTIONS] [COMMAND]

Commands:
  list    List all OATH accounts
  code    Generate codes for accounts
  add     Add a new account
  delete  Delete an account
  access  Manage password protection
  info    Show OATH application info
  reset   Reset OATH application (deletes all accounts)
  help    Print this message or the help of the given subcommand(s)

Options:
  -p, --password <PASSWORD>  Password to unlock
  -o, --show-type            Show OATH type
  -P, --show-period          Show period
  -h, --help                 Print help
  -V, --version              Print version
```

When no command is provided, `yubicli` defaults to listing all accounts.

### Examples

```bash
# List all accounts (default behavior)
yubicli

# Show OATH app info
yubicli info

# Generate code for an account (saved to clipboard if available)
yubicli code myaccount
myaccount  338187

# Generate all codes
yubicli code

# Add a new TOTP account
yubicli add myaccount JBSWY3DPEHPK3PXP

# Add a HOTP account
yubicli add myhotp JBSWY3DPEHPK3PXP -o hotp

# Delete an account
yubicli delete myaccount

# Set password protection
yubicli access set

# Change password
yubicli access change

# Disable password protection
yubicli access clear

# Reset OATH app (deletes all accounts)
yubicli reset -f
```

When password protection is enabled, you'll be prompted for the password before any operation. You can also pass it directly with `-p <password>`.


