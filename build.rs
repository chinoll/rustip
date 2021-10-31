// use std::process::Command;
// use std::env;
// use std::path::Path;
extern crate cc;
fn main() {
    cc::Build::new()
    .file("src/device.c")
    .compile("device");
}