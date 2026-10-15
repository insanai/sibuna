//! The request path allocates nothing: a counting global allocator observes evaluations of
//! browser requests, attacks that need canonicalisation, multipart bodies, mixed inspection
//! modes, observed rule matches, a header padded beyond 8 KiB, and the content encodings and
//! decoded-form detectors. Canonicalising a field longer than 2 KiB uses a buffer each
//! thread allocates once, so one warm-up evaluation runs before counting.
//!
//! Counting allocations needs a `GlobalAlloc` shim, which is `unsafe` to implement; it lives
//! only in this test binary and forwards every call to the system allocator.
#![allow(unsafe_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use sibuna_policy::{Engine, Header, Mode, Modes, RequestView, RuleMatches, waf};

struct Counting;

/// Allocations made by any thread. Relaxed ordering suffices: the test reads the counter on
/// the thread that made the allocations it cares about, after they happened.
static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

// SAFETY: every method forwards to the system allocator with the caller's arguments and
// only counts calls.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: the caller upholds `GlobalAlloc::alloc`'s contract, which `System` shares.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: `ptr` came from `System.alloc` with this layout, as the caller guarantees.
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: as for `dealloc`, and `new_size` is valid per the caller.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

#[test]
fn evaluation_allocates_nothing() {
    let mut engine = Engine::new(16);
    engine.insert_reputation(b"10.0.0.0/8", sibuna_policy::Action::Allow).unwrap();
    let mut mixed = engine.clone();
    mixed.inspection_modes = Modes { sqli: Mode::Audit, xss: Mode::Disabled, ..Modes::default() };
    let body = b"--b\r\nContent-Disposition: form-data; name=\"f\"; \
        filename=\"x\"\r\n\r\nbinary\x00\r\n--b\r\nContent-Disposition: form-data; \
        name=\"t\"\r\n\r\n1%27/**/UnIoN SeLeCt+1\r\n--b--\r\n";
    let long = vec![b'a'; 3000];
    let mut padded = vec![b'x'; 12_000];
    let attack = b"%3Cscript%3Ealert(1)%3E";
    padded[9000..9000 + attack.len()].copy_from_slice(attack);
    let headers = [
        Header { name: b"Content-Type", value: b"multipart/form-data; boundary=b" },
        Header { name: b"Cookie", value: b"session=abc--def; theme=dark" },
        Header { name: b"X-Q", value: &long },
    ];
    let padded_headers = [Header { name: b"X-Pad", value: &padded }];
    let requests = [
        RequestView::new(b"/index.html", b"203.0.113.7", b"Mozilla/5.0 (X11)"),
        RequestView { query: b"q=%3Cscript%3E+x", ..RequestView::new(b"/s", b"::1", b"curl/8") },
        RequestView {
            headers: &headers,
            body,
            ..RequestView::new(b"/upload", b"10.1.2.3", b"GPTBot")
        },
        RequestView {
            headers: &padded_headers,
            ..RequestView::new(b"/p", b"198.51.100.4", b"Mozilla/5.0")
        },
        RequestView {
            query: b"q=%26lt%3Bb%26gt%3B&h=x%0aid&r=1%20union(select%201",
            body: br#"{"c":"\u0027\n\/*!1*/<x onclick =1>"}"#,
            ..RequestView::new(b"/q", b"198.51.100.5", b"Mozilla/5.0")
        },
    ];
    let mut matches = RuleMatches::new();
    assert!(waf::inspect_request(engine.signatures(), &requests[3]).is_some());
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    let mut denied = 0;
    for _ in 0..1000 {
        for request in &requests {
            denied += usize::from(engine.evaluate(request).rule_name.starts_with("waf:"));
            denied += usize::from(
                mixed.evaluate_with_matches(request, &mut matches).rule_name.starts_with("waf:"),
            );
            denied += usize::from(waf::inspect_request(engine.signatures(), request).is_some());
        }
    }
    assert_eq!(ALLOCATIONS.load(Ordering::Relaxed), before);
    assert!(denied > 0);
}
