fn main() {
    println!("cargo:rerun-if-changed=src/controlbits/*");

    cc::Build::new()
        .file("src/controlbits/controlbits.c")
        .compile("controlbits");
}
