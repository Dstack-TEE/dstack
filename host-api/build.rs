fn main() {
    prpc_build::configure()
        .out_dir(std::env::var_os("OUT_DIR").unwrap())
        .mod_prefix("super::")
        .build_scale_ext(false)
        .disable_service_name_emission()
        .disable_package_emission()
        .enable_serde_extension()
        .compile_dir("./proto")
        .expect("failed to compile proto files");
}
