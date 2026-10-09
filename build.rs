// This build script configures the Rust build to compile the C++ source file
// 'guardrails_bridge.cpp' using the cc crate, sets it to use C++17, and ensures
// Cargo rebuilds if the source or header changes.
fn main() {
    // The C++ bridge is for native hosts; WebAssembly builds use the Rust core only.
    if std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("wasm32") {
        return;
    }
    cc::Build::new()
        .cpp(true)
        .file("cpp/guardrails_bridge.cpp")
        .include("cpp")
        .std("c++17")
        .compile("guardrails_bridge");

    println!("cargo:rerun-if-changed=cpp/guardrails_bridge.cpp");
    println!("cargo:rerun-if-changed=cpp/guardrails_bridge.h");
}
