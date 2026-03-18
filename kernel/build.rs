// kernel/build.rs — pass the custom linker script to the linker.

fn main() {
    // Tell the linker to use our custom script with an absolute path.
    // Relative `-Tkernel.ld` can fail depending on the linker working dir.
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR is always set by Cargo");
    let script_path = format!("{manifest_dir}/kernel.ld");
    println!("cargo:rustc-link-arg=-T{script_path}");

    // Re-run this build script only when the linker script changes.
    println!("cargo:rerun-if-changed=kernel.ld");
}
