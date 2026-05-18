//! Optional libxdp dispatcher attach path.
//!
//! When `lqos.conf` sets `xdp_attach_mode = "libxdp"` (or the CLI flag
//! `--xdp-attach-mode=libxdp` is passed), `lqos_kernel::attach_xdp_best_available`
//! dispatches here instead of calling `bpf_xdp_attach()` directly. Wrapping the
//! XDP program in a libxdp dispatcher lets other XDP programs run on the same
//! interface in priority order — required for composability with external
//! tools (DSCP markers, observability probes, etc.).
//!
//! ## Lifecycle
//!
//! * **Attach:** `xdp_program__from_fd(prog_fd)` wraps the already-loaded
//!   skeleton program, `xdp_program__set_run_prio(priority)` sets where it sits
//!   in the dispatcher chain, `xdp_program__attach()` performs the attach.
//!   libxdp creates the dispatcher on the first attach and extends it on
//!   subsequent attaches by any program (us or external).
//!
//! * **Detach:** `xdp_program__from_id(prog_id)` reconstructs a handle and
//!   `xdp_program__detach(prog, ifindex)` removes us from the dispatcher.
//!   If we're the last user, libxdp tears down the dispatcher entirely.
//!   See `unload_via_libxdp` for the fallback chain when we can't reconstruct
//!   the handle.
//!
//! ## Fail-safe semantics
//!
//! If the admin explicitly requested libxdp mode and the dispatcher cannot be
//! created (kernel without `BPF_PROG_TYPE_EXT`, libxdp internal error,
//! permissions, etc.), this returns an error and `lqosd` exits cleanly. We do
//! NOT fall back silently to raw mode — silent fallback would leave any
//! companion XDP programs (markers, samplers) dangling without a dispatcher
//! to attach to.

use anyhow::{Error, Result};
use libxdp_sys::{
    bpf_program__set_autoload, libxdp_set_print, xdp_attach_mode, xdp_attach_mode_XDP_MODE_NATIVE,
    xdp_attach_mode_XDP_MODE_SKB, xdp_program, xdp_program__attach, xdp_program__close,
    xdp_program__detach, xdp_program__from_bpf_obj, xdp_program__from_id,
    xdp_program__set_run_prio,
};
use std::ffi::CString;
use std::sync::Once;

/// Print hook: forwards libxdp's internal log messages to tracing so we can
/// see the real reason a dispatcher attach failed. Without this, libxdp prints
/// to its own internal sink and we only see our outer error.
extern "C" fn libxdp_print_to_tracing(
    level: libxdp_sys::libxdp_print_level,
    fmt: *const std::os::raw::c_char,
    ap: *mut libxdp_sys::__va_list_tag,
) -> std::os::raw::c_int {
    use std::os::raw::{c_char, c_int};
    // Format the variadic message into a fixed-size buffer.
    let mut buf = [0u8; 1024];
    unsafe extern "C" {
        fn vsnprintf(
            buf: *mut c_char,
            sz: usize,
            fmt: *const c_char,
            ap: *mut libxdp_sys::__va_list_tag,
        ) -> c_int;
    }
    let n = unsafe { vsnprintf(buf.as_mut_ptr() as *mut c_char, buf.len(), fmt, ap) };
    if n <= 0 {
        return 0;
    }
    let len = std::cmp::min(n as usize, buf.len() - 1);
    // Trim trailing newline
    let trimmed = std::str::from_utf8(&buf[..len])
        .unwrap_or("<non-utf8>")
        .trim_end_matches('\n');
    // Map libxdp severity → tracing level
    use libxdp_sys::{
        libxdp_print_level_LIBXDP_DEBUG, libxdp_print_level_LIBXDP_INFO,
        libxdp_print_level_LIBXDP_WARN,
    };
    match level {
        x if x == libxdp_print_level_LIBXDP_WARN => warn!(target: "libxdp", "{}", trimmed),
        x if x == libxdp_print_level_LIBXDP_INFO => info!(target: "libxdp", "{}", trimmed),
        x if x == libxdp_print_level_LIBXDP_DEBUG => debug!(target: "libxdp", "{}", trimmed),
        _ => warn!(target: "libxdp", "{}", trimmed),
    }
    n
}

static INIT_LIBXDP_PRINT: Once = Once::new();

/// Install the print hook on first use. Idempotent.
fn ensure_print_hook() {
    INIT_LIBXDP_PRINT.call_once(|| unsafe {
        libxdp_set_print(Some(libxdp_print_to_tracing));
    });
}
use std::os::raw::c_int;
use tracing::{debug, info, warn};

use crate::lqos_kernel::bpf;

/// IS_ERR check for libxdp pointers (libxdp uses the Linux kernel
/// ERR_PTR pattern: pointer values in the range `-4095..=-1` encode errno).
fn err_ptr(ptr: *mut xdp_program) -> Option<i32> {
    let v = ptr as isize;
    if v < 0 && v >= -4095 { Some(-v as i32) } else { None }
}

/// Disable the BPF skeleton's auto-load for `xdp_prog`.
///
/// MUST be called between `lqos_kern_open` and `lqos_kern_load` when running in
/// libxdp mode. The skeleton's load would otherwise load `xdp_prog` as a
/// regular `BPF_PROG_TYPE_XDP` program, which cannot then be wrapped in a
/// libxdp dispatcher (sub-programs of a dispatcher must be loaded as
/// `BPF_PROG_TYPE_EXT` — kernel won't change a loaded program's type).
///
/// With autoload disabled, the skeleton still loads maps, TC programs, and
/// other BPF objects normally; only `xdp_prog` is skipped. libxdp then owns
/// `xdp_prog`'s lifecycle and loads it as EXT during attach.
///
/// # Safety
/// Caller must pass a valid `skeleton` pointer returned by `lqos_kern_open`.
pub unsafe fn disable_xdp_prog_autoload(skeleton: *mut bpf::lqos_kern) {
    // The skeleton's `progs.xdp_prog` is a `*mut libbpf_sys::bpf_program`
    // (or equivalent opaque type from the bindings.rs). libxdp-sys exposes
    // its own `bpf_program` opaque type. Both refer to the same underlying
    // libbpf object; we cast the pointer since Rust's type system can't see
    // through the FFI opaque boundary.
    let prog =
        unsafe { (*skeleton).progs.xdp_prog as *mut libxdp_sys::bpf_program };
    unsafe { bpf_program__set_autoload(prog, false) };
    debug!("libxdp: disabled skeleton autoload for xdp_prog (will load as EXT via dispatcher)");
}

/// Attach the LibreQoS XDP program to `ifindex` via the libxdp dispatcher.
///
/// `priority` controls where this program sits in the dispatcher chain:
/// LOWER numbers run later. LibreQoS performs `XDP_REDIRECT` (terminating),
/// so it should run LAST — use a low priority (default 10 in `lqos_config`).
///
/// REQUIRES that the skeleton's `xdp_prog` was marked non-autoload via
/// `disable_xdp_prog_autoload` BEFORE `lqos_kern_load` was called. Otherwise
/// `xdp_prog` is already loaded as `BPF_PROG_TYPE_XDP` and libxdp cannot
/// re-type it to `BPF_PROG_TYPE_EXT` (which dispatcher sub-programs require).
///
/// # Safety
/// Caller must pass a valid `skeleton` pointer returned by `lqos_kern_open`
/// followed by `lqos_kern_load`. The skeleton must outlive the attached
/// program.
pub unsafe fn attach_via_libxdp(
    skeleton: *mut bpf::lqos_kern,
    ifindex: u32,
    iface_name: &str,
    priority: u32,
) -> Result<()> {
    ensure_print_hook();
    // Get the bpf_object from the skeleton. Skeleton struct from bpftool gen
    // skeleton has `.obj` as `*mut bpf_object`. The libxdp function takes the
    // bpf_object plus the BPF program SECTION name ("xdp" in lqos_kern.c).
    let obj = unsafe { (*skeleton).obj as *mut libxdp_sys::bpf_object };
    if obj.is_null() {
        return Err(Error::msg(format!(
            "libxdp attach: skeleton bpf_object is null on {iface_name}"
        )));
    }
    let section_name = CString::new("xdp").map_err(Error::new)?;

    let prog = unsafe { xdp_program__from_bpf_obj(obj, section_name.as_ptr()) };
    if let Some(errno) = err_ptr(prog) {
        return Err(Error::msg(format!(
            "libxdp attach: xdp_program__from_bpf_obj failed on {iface_name} (errno={errno}). \
             Hint: was disable_xdp_prog_autoload() called before lqos_kern_load?"
        )));
    }
    if prog.is_null() {
        return Err(Error::msg(format!(
            "libxdp attach: xdp_program__from_bpf_obj returned null on {iface_name}"
        )));
    }

    unsafe { xdp_program__set_run_prio(prog, priority) };

    // Try NATIVE (driver) first, fall back to SKB. libxdp dispatcher does not
    // support HW offload mode, which is fine: HW offload is rare in production
    // (Netronome NFP only) and the LibreQoS user base runs DRV mode anyway.
    let modes: [(xdp_attach_mode, &str); 2] = [
        (xdp_attach_mode_XDP_MODE_NATIVE, "DRV"),
        (xdp_attach_mode_XDP_MODE_SKB, "SKB"),
    ];

    let mut last_err: c_int = 0;
    for (mode, label) in modes {
        let err = unsafe { xdp_program__attach(prog, ifindex as i32, mode, 0) };
        if err == 0 {
            info!(
                "libxdp dispatcher attached on {} (mode {}, priority {})",
                iface_name, label, priority
            );
            // NOTE: do NOT call xdp_program__close — that would detach.
            // The kernel keeps the dispatcher pinned to the interface; the
            // handle's lifetime is decoupled.
            return Ok(());
        }
        debug!(
            "libxdp dispatcher attach in {} mode failed on {} (err={}); trying next mode",
            label, iface_name, err
        );
        last_err = err;
    }

    // All modes failed. Close handle, return loud error.
    unsafe { xdp_program__close(prog) };
    Err(Error::msg(format!(
        "libxdp dispatcher attach failed on {iface_name} in all modes (last errno={last_err}). \
         Hint: kernel must support BPF_PROG_TYPE_EXT (Linux >=5.10) for libxdp \
         composition. If kernel is older, set xdp_attach_mode = \"raw\" in lqos.conf."
    )))
}

/// Detach LibreQoS's XDP program from `ifindex` via libxdp.
///
/// Idempotent — returns `Ok(())` if no libxdp-attached program is found.
/// Falls through to the caller's raw-detach fallback in `unload_xdp_from_interface`
/// if libxdp detach doesn't apply (e.g., interface was attached in raw mode).
///
/// Strategy:
///   1. Get the currently-attached XDP program ID on `ifindex` via netlink (we
///      use libxdp's `xdp_program__from_id` chain). If it's a dispatcher with
///      our program inside, libxdp's detach API removes us cleanly.
///   2. If no libxdp dispatcher is present, return Ok and let the raw-detach
///      fallback run.
///
/// # Safety
/// Calls into libxdp C library; no Rust invariants required.
pub unsafe fn detach_via_libxdp(ifindex: u32, iface_name: &str) -> Result<()> {
    // Discover the program currently attached on the interface. We use
    // `bpf_xdp_query` (libbpf) to get the program ID, then wrap it with
    // `xdp_program__from_id` so libxdp can recognize whether it's a
    // dispatcher and find our sub-program inside.
    let mut prog_id: u32 = 0;
    let err = unsafe {
        // bpf_xdp_query_id signature: int bpf_xdp_query_id(int ifindex, int flags, __u32 *prog_id)
        libxdp_sys::bpf_xdp_query_id(ifindex as i32, 0, &mut prog_id)
    };
    if err != 0 {
        debug!(
            "libxdp detach: bpf_xdp_query_id failed on {} (err={}); no XDP attached?",
            iface_name, err
        );
        return Ok(());
    }
    if prog_id == 0 {
        debug!(
            "libxdp detach: no XDP program attached on {}; nothing to do",
            iface_name
        );
        return Ok(());
    }

    let prog = unsafe { xdp_program__from_id(prog_id) };
    if let Some(errno) = err_ptr(prog) {
        // Couldn't open by ID — fall through to raw fallback. This typically
        // happens if the attached program isn't a libxdp dispatcher OR if our
        // process lacks BPF visibility into it.
        warn!(
            "libxdp detach: xdp_program__from_id({}) failed on {} (errno={}); leaving for raw fallback",
            prog_id, iface_name, errno
        );
        return Ok(());
    }
    if prog.is_null() {
        return Ok(());
    }

    // Try the canonical detach mode first; libxdp internally figures out the
    // right mode for the dispatcher.
    let err = unsafe {
        xdp_program__detach(prog, ifindex as i32, xdp_attach_mode_XDP_MODE_NATIVE, 0)
    };
    if err == 0 {
        info!("libxdp dispatcher detached on {}", iface_name);
        unsafe { xdp_program__close(prog) };
        return Ok(());
    }

    // Retry in SKB mode in case the dispatcher was attached there.
    let err2 = unsafe {
        xdp_program__detach(prog, ifindex as i32, xdp_attach_mode_XDP_MODE_SKB, 0)
    };
    unsafe { xdp_program__close(prog) };
    if err2 == 0 {
        info!("libxdp dispatcher detached on {} (SKB mode)", iface_name);
        return Ok(());
    }

    // Both modes failed — log but don't error. The aggressive raw-detach
    // cascade in `unload_xdp_from_interface` will clean up regardless
    // (`bpf_xdp_attach(ifindex, -1, ...)` detaches anything XDP-shaped,
    // including a libxdp dispatcher). The libxdp-first attempt is an
    // optimization that gives cleaner teardown when it works; the raw
    // cascade is the correctness guarantee.
    warn!(
        "libxdp detach: both modes failed on {} (DRV err={}, SKB err={}); raw cascade will clean up",
        iface_name, err, err2
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn err_ptr_decodes_errno() {
        assert_eq!(err_ptr((-22isize) as *mut xdp_program), Some(22));
        assert_eq!(err_ptr((-1isize) as *mut xdp_program), Some(1));
        assert_eq!(err_ptr((-4095isize) as *mut xdp_program), Some(4095));
    }

    #[test]
    fn err_ptr_passes_valid_pointers() {
        let valid = 0x7fff_ffff_ffff as *mut xdp_program;
        assert_eq!(err_ptr(valid), None);
        // Null isn't an err ptr; caller checks is_null separately.
        assert_eq!(err_ptr(std::ptr::null_mut()), None);
    }

    #[test]
    fn err_ptr_rejects_below_errno_range() {
        // Out of the conventional IS_ERR range
        assert_eq!(err_ptr((-4096isize) as *mut xdp_program), None);
    }
}
