//! The front desk: the process that talks to the host.
//!
//! It reads framed requests from USB HID (or TCP in the emulator), answers
//! get-version and malformed requests itself, and hands every other request
//! to the approver, which holds the seed and the touch pad. Nothing in this
//! process can sign or decide that the pad was touched.
use eth_burner::protocol::ErrorCode;
use eth_burner::{ipc, transport, VERSION};

struct Forward(ipc::Approver);

impl transport::Handler for Forward {
    fn request(&mut self, ty: u8, message: &[u8]) -> Vec<u8> {
        self.0.call(ty, message).unwrap_or_else(|why| {
            log::error!("request not answered: {why}");
            transport::error_frame(ErrorCode::Internal, why)
        })
    }
}

fn main() -> ! {
    log_server::init_wait().unwrap();
    log::set_max_level(log::LevelFilter::Info);
    log::info!("eth-burner front desk {VERSION}, PID {}", xous::process::id());
    let approver = ipc::Approver::connect();
    log::info!("connected to the approver");
    transport::serve(Forward(approver))
}
