use std::{fs, path::Path};

fn main() {
    let native = Path::new("native");
    let mut build = cc::Build::new();
    build
        .include(native)
        .include(native.join("vendor/lwip/src/include"))
        .file(native.join("krtek_lwip.c"))
        .flag_if_supported("-std=c11")
        .flag_if_supported("-fvisibility=hidden")
        .flag_if_supported("-ffunction-sections")
        .flag_if_supported("-fdata-sections")
        // Stock ND retains unused declarations when SLAAC/RS are disabled.
        // The standalone native gate checks the port with strict warnings.
        .flag_if_supported("-Wno-unused-parameter")
        .flag_if_supported("-Wno-unused-variable");
    // cc consumes Cargo's target-specific CC/AR and NDK sysroot configuration.
    for line in fs::read_to_string(native.join("sources.txt"))
        .expect("read pinned lwIP source list")
        .lines()
    {
        if !line.is_empty() {
            build.file(native.join("vendor/lwip").join(line));
        }
    }
    println!("cargo::rerun-if-changed=native");
    build.compile("krtek_lwip");
}
