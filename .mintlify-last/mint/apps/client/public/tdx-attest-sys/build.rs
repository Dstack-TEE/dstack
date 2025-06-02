use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=csrc/tdx_attest.c");
    println!("cargo:rerun-if-changed=csrc/qgs_msg_lib.cpp");
    let output_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindgen::Builder::default()
        .header("bindings.h")
        .default_enum_style(bindgen::EnumVariation::ModuleConsts)
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(output_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
    cc::Build::new()
        .file("csrc/tdx_attest.c")
        .file("csrc/qgs_msg_lib.cpp")
        .compile("tdx_attest");
}
