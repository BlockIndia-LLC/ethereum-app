//! The one channel between the two processes.
//!
//! The front desk lends the approver a buffer holding `type || message`, as it
//! came from the host, and blocks; the approver answers in the same buffer
//! with a response frame. There is one message type, so the only thing the
//! front desk can make the approver do is treat a request as the host's.
//!
//! The approver registers its name for a single connection (xous-names counts
//! them): once the front desk has it, no other process can get one.
use crate::protocol::ErrorCode;
use crate::transport::error_frame;

pub const SERVER_NAME: &str = "_Ethereum burner approver_";
const OP_REQUEST: usize = 1;
const PAGE: usize = 4096;

/// The front desk's end.
pub struct Approver(xous::CID);

impl Approver {
    /// Waits until the approver has started.
    pub fn connect() -> Self {
        let xns = xous_names::XousNames::new().expect("xous-names");
        Approver(xns.request_connection_blocking(SERVER_NAME).expect("can't reach the approver"))
    }

    /// Hand one request over and wait for its response frame, which for a
    /// signing request is as long as the person takes to touch the pad.
    pub fn call(&self, ty: u8, message: &[u8]) -> Result<Vec<u8>, &'static str> {
        let len = 1 + message.len();
        let size = len.div_ceil(PAGE) * PAGE;
        let mut range = xous::map_memory(None, None, size, xous::MemoryFlags::R | xous::MemoryFlags::W)
            .map_err(|_| "out of memory")?;
        // safety: the range was just mapped, readable and writable, for this call only
        let buf = unsafe { range.as_slice_mut::<u8>() };
        buf[0] = ty;
        buf[1..len].copy_from_slice(message);
        let sent = xous::send_message(
            self.0,
            xous::Message::new_lend_mut(OP_REQUEST, range, None, xous::MemorySize::new(len)),
        );
        let reply = match sent {
            Ok(xous::Result::MemoryReturned(_, Some(valid))) if valid.get() <= size => {
                // safety: the lend is over, the range is ours again
                Ok(unsafe { range.as_slice::<u8>() }[..valid.get()].to_vec())
            }
            _ => Err("the approver didn't answer"),
        };
        xous::unmap_memory(range).ok();
        reply
    }
}

/// The approver's end: answer requests with `handle(type, message)`, which
/// returns a response frame.
pub fn serve(mut handle: impl FnMut(u8, &[u8]) -> Vec<u8>) -> ! {
    let xns = xous_names::XousNames::new().expect("xous-names");
    let sid = xns.register_name(SERVER_NAME, Some(1)).expect("can't register the approver");
    log::info!("approver ready: one connection, for the front desk");
    loop {
        let mut envelope = xous::receive_message(sid).expect("receive");
        let sender = envelope.sender;
        // anything that isn't a mutable lend is dropped, which returns it unanswered
        let Some(mem) = envelope.body.memory_message_mut() else { continue };
        let (id, mut range) = (mem.id, mem.buf);
        let given = mem.valid.map_or(0, |v| v.get());
        // safety: the kernel mapped the lent range into this process for the length of the lend
        let buf = unsafe { range.as_slice_mut::<u8>() };
        let reply = if id == OP_REQUEST && (1..=buf.len()).contains(&given) {
            // a copy: the answer is written over the request
            let request = buf[..given].to_vec();
            handle(request[0], &request[1..])
        } else {
            error_frame(ErrorCode::Unsupported, "not a request")
        };
        let n = reply.len().min(buf.len());
        buf[..n].copy_from_slice(&reply[..n]);
        xous::return_memory_offset_valid(sender, range, None, xous::MemorySize::new(n)).ok();
        // already returned: the envelope must not return it again when dropped
        core::mem::forget(envelope);
    }
}
