fn main() {
    cc::Build::new()
        .cpp(true)
        .file("cpp/guardrails_bridge.cpp")
        .include("cpp")
        .std("c++17")
        .compile("guardrails_bridge");

    println!("cargo:rerun-if-changed=cpp/guardrails_bridge.cpp");
    println!("cargo:rerun-if-changed=cpp/guardrails_bridge.h");
}
