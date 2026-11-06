//! USB CCID transport: talk to the YubiKey directly over USB, no pcscd.
//!
//! Pure Rust via `nusb` (no libusb, no C code, no system dependencies).
//! Implements just enough of USB CCID 1.1 for OATH on slot 0:
//! IccPowerOn, XfrBlock and (best-effort, write-only) IccPowerOff.
//! Short APDUs plus the 0x61 GET RESPONSE chaining in `session.rs`
//! cover everything OATH needs.

use std::time::Duration;

use nusb::descriptors::TransferType;
use nusb::transfer::{Bulk, Direction, In, Out};
use nusb::MaybeFuture;

use crate::session::Error;

const YUBICO_VID: u16 = 0x1050;
const CCID_CLASS: u8 = 0x0B;

const PC_TO_RDR_ICC_POWER_ON: u8 = 0x62;
const PC_TO_RDR_ICC_POWER_OFF: u8 = 0x63;
const PC_TO_RDR_XFR_BLOCK: u8 = 0x6F;
const RDR_TO_PC_DATA_BLOCK: u8 = 0x80;

const WRITE_TIMEOUT: Duration = Duration::from_secs(5);
// Generous: a touch-required applet holds the transfer until touch/timeout.
const READ_TIMEOUT: Duration = Duration::from_secs(15);

pub struct UsbCcidDevice {
    // Held to keep the interface claimed for the device lifetime.
    #[allow(dead_code)]
    iface: nusb::Interface,
    ep_out: nusb::Endpoint<Bulk, Out>,
    ep_in: nusb::Endpoint<Bulk, In>,
    seq: u8,
}

impl UsbCcidDevice {
    /// Open the first YubiKey exposing a CCID interface, claim it and
    /// power slot 0. Mirrors the old PC/SC policy: error on zero or
    /// multiple devices instead of guessing.
    pub fn open_first() -> Result<Self, Error> {
        let mut found = Vec::new();
        for info in nusb::list_devices()
            .wait()
            .map_err(|e| Error::Usb(format!("cannot list USB devices: {}", e)))?
        {
            if info.vendor_id() != YUBICO_VID {
                continue;
            }
            let iface_no = info
                .interfaces()
                .find(|i| i.class() == CCID_CLASS)
                .map(|i| i.interface_number());
            if let Some(iface_no) = iface_no {
                found.push((info, iface_no));
            }
        }
        if found.is_empty() {
            return Err(Error::NoReaders);
        }
        if found.len() > 1 {
            eprintln!("warning: more than one YubiKey found, aborting for safety:");
            for (info, iface_no) in &found {
                eprintln!(
                    "  bus {} addr {:03} vid:pid {:04X}:{:04X} product={:?} ccid_iface={}",
                    info.bus_id(),
                    info.device_address(),
                    info.vendor_id(),
                    info.product_id(),
                    info.product_string().unwrap_or("YubiKey"),
                    iface_no,
                );
            }
            eprintln!("unplug all but one and retry.");
            return Err(Error::MultipleDevices);
        }
        let (info, iface_no) = found.remove(0);

        let device = info
            .open()
            .wait()
            .map_err(|e| {
                Error::Usb(format!(
                    "cannot open YubiKey USB device: {} (udev rule or root needed; or stop any other program using the key)",
                    e
                ))
            })?;

        let iface = device
            .claim_interface(iface_no)
            .wait()
            .map_err(|e| {
                Error::Usb(format!(
                    "cannot claim CCID interface: {} (is another program using the key?)",
                    e
                ))
            })?;

        let (mut ep_out_addr, mut ep_in_addr) = (None, None);
        for alt in iface.descriptors() {
            if alt.class() != CCID_CLASS {
                continue;
            }
            for ep in alt.endpoints() {
                match (ep.direction(), ep.transfer_type()) {
                    (Direction::Out, TransferType::Bulk) => ep_out_addr = Some(ep.address()),
                    (Direction::In, TransferType::Bulk) => ep_in_addr = Some(ep.address()),
                    _ => {}
                }
            }
        }
        let (ep_out_addr, ep_in_addr) = match (ep_out_addr, ep_in_addr) {
            (Some(o), Some(i)) => (o, i),
            _ => return Err(Error::Usb("CCID interface has no bulk endpoints".into())),
        };

        let ep_out = iface
            .endpoint::<Bulk, Out>(ep_out_addr)
            .map_err(|e| Error::Usb(format!("cannot open bulk-out endpoint: {}", e)))?;
        let mut ep_in = iface
            .endpoint::<Bulk, In>(ep_in_addr)
            .map_err(|e| Error::Usb(format!("cannot open bulk-in endpoint: {}", e)))?;

        // Drain stale responses (e.g. the unanswered PowerOff reply left
        // behind by a previous run's Drop) so the first real reply we read
        // is the one to our own PowerOn.
        let mps = ep_in.max_packet_size().max(1);
        while ep_in
            .transfer_blocking(
                nusb::transfer::Buffer::new(mps * 64),
                Duration::from_millis(100),
            )
            .into_result()
            .is_ok()
        {
            // Discard the stale message and keep draining.
        }

        let mut dev = Self {
            iface,
            ep_out,
            ep_in,
            seq: 0,
        };
        // Power on: automatic voltage first, 5V as fallback.
        match dev.power_on(0x00) {
            Ok(_) => {}
            Err(first) => dev.power_on(0x01).map_err(|e| {
                Error::Usb(format!("CCID power-on failed (auto: {}; 5V: {})", first, e))
            })?,
        }
        Ok(dev)
    }

    /// Send one APDU, return the full RAPDU (data + SW).
    pub fn transmit_apdu(&mut self, apdu: &[u8]) -> Result<Vec<u8>, Error> {
        // extra = [bBWI, wLevelParameter(LE)]
        let seq = self.send(PC_TO_RDR_XFR_BLOCK, apdu, [0x00, 0x00, 0x00])?;
        self.recv(RDR_TO_PC_DATA_BLOCK, seq)
    }

    fn power_on(&mut self, power_select: u8) -> Result<(), Error> {
        // dwLength=0, extra = [bPowerSelect, 00, 00]
        let seq = self.send(PC_TO_RDR_ICC_POWER_ON, &[], [power_select, 0x00, 0x00])?;
        self.recv(RDR_TO_PC_DATA_BLOCK, seq).map(|_| ())
    }

    fn send(&mut self, msg_type: u8, payload: &[u8], extra: [u8; 3]) -> Result<u8, Error> {
        let seq = self.seq;
        let mut msg = Vec::with_capacity(10 + payload.len());
        msg.push(msg_type);
        msg.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        msg.push(0x00); // bSlot
        msg.push(seq);
        msg.extend_from_slice(&extra);
        msg.extend_from_slice(payload);
        self.seq = self.seq.wrapping_add(1);
        self.ep_out
            .transfer_blocking(msg.into(), WRITE_TIMEOUT)
            .into_result()
            .map_err(|e| Error::Usb(format!("CCID bulk write failed: {}", e)))?;
        Ok(seq)
    }

    /// Read one full CCID message (10-byte header + dwLength payload).
    fn recv(&mut self, expect_type: u8, expect_seq: u8) -> Result<Vec<u8>, Error> {
        // IN length must be a nonzero multiple of max packet size.
        let mps = self.ep_in.max_packet_size().max(1);
        let buf = self
            .ep_in
            .transfer_blocking(nusb::transfer::Buffer::new(mps * 64), READ_TIMEOUT)
            .into_result()
            .map_err(|e| Error::Usb(format!("CCID bulk read failed: {}", e)))?;
        let msg: &[u8] = &buf;
        if msg.len() < 10 {
            return Err(Error::Usb(format!(
                "short CCID message: {} bytes",
                msg.len()
            )));
        }
        let len = u32::from_le_bytes([msg[1], msg[2], msg[3], msg[4]]) as usize;
        if msg.len() < 10 + len {
            return Err(Error::Usb(format!(
                "truncated CCID message: {} of {} bytes",
                msg.len(),
                10 + len
            )));
        }
        if msg[0] != expect_type {
            return Err(Error::Usb(format!(
                "unexpected CCID message 0x{:02X}, want 0x{:02X} (status=0x{:02X} err=0x{:02X})",
                msg[0], expect_type, msg[7], msg[8]
            )));
        }
        if msg[6] != expect_seq {
            return Err(Error::Usb(format!(
                "CCID sequence mismatch: got {}, want {}",
                msg[6], expect_seq
            )));
        }
        if msg[7] & 0x40 != 0 || msg[8] != 0x00 {
            return Err(Error::Usb(format!(
                "CCID command failed: status=0x{:02X} error=0x{:02X}",
                msg[7], msg[8]
            )));
        }
        Ok(msg[10..10 + len].to_vec())
    }
}

impl Drop for UsbCcidDevice {
    fn drop(&mut self) {
        // Best effort and write-only: never block teardown on a read.
        let _ = self
            .ep_out
            .transfer_blocking(
                vec![PC_TO_RDR_ICC_POWER_OFF, 0, 0, 0, 0, 0x00, self.seq, 0, 0, 0].into(),
                Duration::from_secs(1),
            )
            .into_result();
    }
}
