//! The front desk: the process that talks to the host.
//!
//! It reads framed requests from USB HID (or TCP in the emulator), answers
//! get-version and malformed requests itself, and hands every other request
//! to the approver, which holds the seed and the touch pad. Nothing in this
//! process can sign or decide that the pad was touched.
use eth_burner::protocol::{self, ErrorCode, Request, TYPE_CUSTOM};
use eth_burner::{ipc, transport, VERSION};

struct Forward {
    approver: ipc::Approver,
    /// What this process found when it tried to reach the keystore, for `status`.
    keystore: &'static str,
}

impl transport::Handler for Forward {
    fn request(&mut self, ty: u8, message: &[u8]) -> Vec<u8> {
        let reply = self.approver.call(ty, message).unwrap_or_else(|why| {
            log::error!("request not answered: {why}");
            transport::error_frame(ErrorCode::Internal, why)
        });
        // `status` is answered by both processes: the approver's line, then this one's
        if ty == TYPE_CUSTOM && protocol::decode_request(message) == Ok(Request::Status) {
            if let Some(theirs) = protocol::message_of(&reply) {
                let both = format!("{theirs}\n{}", self.keystore);
                return protocol::encode_frame(TYPE_CUSTOM, &protocol::message_response(&both));
            }
        }
        reply
    }
}

/// Try what a front desk that had been taken over would try: a connection to
/// the keystore, where the seed is. Run once the approver is up, so the
/// approver has made its own connection first.
#[cfg(target_os = "xous")]
fn try_keystore() -> &'static str {
    let Ok(xns) = xous_names::XousNames::new() else { return "front desk: can't reach xous-names" };
    match xns.request_connection(keystore_api::SERVER_NAME_KEYS) {
        Err(_) => "front desk: the keystore refused a connection",
        Ok(_) => "front desk: the keystore ACCEPTED a connection (it is open to every process)",
    }
}

#[cfg(not(target_os = "xous"))]
fn try_keystore() -> &'static str {
    "front desk: emulator, no keystore"
}

fn main() -> ! {
    log_server::init_wait().unwrap();
    log::set_max_level(log::LevelFilter::Info);
    log::info!("eth-burner front desk {VERSION}, PID {}", xous::process::id());
    let approver = ipc::Approver::connect();
    log::info!("connected to the approver");
    let keystore = try_keystore();
    log::info!("{keystore}");
    transport::serve(Forward { approver, keystore })
}
