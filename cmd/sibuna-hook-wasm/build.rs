//! Shrinks the stack of the WebAssembly build. The default stack of one mebibyte makes
//! the memory start at 17 pages, above the default `memory_pages` of 4 (SID 0030).

fn main() {
    let target = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    if target == "wasm32" {
        println!("cargo:rustc-link-arg=-zstack-size=32768");
    }
}
