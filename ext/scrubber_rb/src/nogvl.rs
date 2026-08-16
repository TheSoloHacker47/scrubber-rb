//! Releasing the GVL around long scans.
//!
//! Scanning a 50MB log file takes long enough that holding the GVL would stall
//! every other thread in a Puma worker. The rule that makes this safe: the
//! input is copied into a Rust-owned buffer *before* the GVL is released, and
//! nothing inside the closure touches a Ruby object.

use std::ffi::c_void;
use std::panic::{catch_unwind, AssertUnwindSafe};

/// Inputs at least this large are scanned with the GVL released. Below it the
/// release/reacquire round trip costs more than the scan.
pub const GVL_THRESHOLD: usize = 64 * 1024;

/// Run `func` with the GVL released.
///
/// # Safety contract
///
/// `func` must not call any Ruby C API function or touch any `VALUE`. Callers
/// in this crate satisfy that by operating only on an owned `Vec<u8>`.
pub fn without_gvl<F, R>(func: F) -> std::thread::Result<R>
where
    F: FnOnce() -> R,
{
    struct Payload<F, R> {
        func: Option<F>,
        result: Option<std::thread::Result<R>>,
    }

    unsafe extern "C" fn trampoline<F, R>(data: *mut c_void) -> *mut c_void
    where
        F: FnOnce() -> R,
    {
        let payload = &mut *(data as *mut Payload<F, R>);
        if let Some(func) = payload.func.take() {
            // A panic must not unwind across the C frame Ruby put us in, so it
            // is caught here and re-raised on the Ruby side as
            // Scrubber::InternalError.
            payload.result = Some(catch_unwind(AssertUnwindSafe(func)));
        }
        std::ptr::null_mut()
    }

    let mut payload = Payload {
        func: Some(func),
        result: None,
    };

    unsafe {
        rb_sys::rb_thread_call_without_gvl(
            Some(trampoline::<F, R>),
            std::ptr::addr_of_mut!(payload) as *mut c_void,
            // No unblocking function: the scan is pure CPU work with no
            // syscalls to interrupt, and it always terminates (the regex engine
            // is linear-time). Ruby will simply defer the interrupt.
            None,
            std::ptr::null_mut(),
        );
    }

    payload
        .result
        .take()
        .unwrap_or_else(|| Err(Box::new("scan closure never ran")))
}

/// Run `func`, converting a panic into a `Result` instead of an abort.
pub fn guarded<F, R>(func: F) -> std::thread::Result<R>
where
    F: FnOnce() -> R,
{
    catch_unwind(AssertUnwindSafe(func))
}

/// Human-readable text for whatever `catch_unwind` handed back.
pub fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "unknown panic in the scrubber_rb native extension".to_string()
    }
}
