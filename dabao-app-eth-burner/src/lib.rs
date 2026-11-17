//! Ethereum burner signer for the dabao (no screen, no PIN), as two processes.
//!
//! * `eth-burner`, the front desk (`main.rs`): the only one that talks to the
//!   host, over USB HID (or TCP in the emulator, see `transport`). It decodes
//!   the framing, answers get-version, and passes everything else on.
//! * `eth-approver` (`approver.rs`, `signer`): holds the seed, watches the
//!   touch pad and signs. It only hears from the front desk, through one
//!   message type (`ipc`).
//!
//! Xous gives each process its own address space, enforced by the chip's MMU:
//! a bug in the code that parses what the host sends can't read the seed out
//! of the approver's memory or skip the touch. What that does not cover is in
//! the README ("Two processes").
pub mod confirm;
pub mod ipc;
#[allow(dead_code)] // error codes and helpers the burner doesn't use
pub mod protocol;
pub mod signer;
pub mod transport;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
