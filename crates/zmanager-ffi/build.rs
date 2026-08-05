fn main() {
    uniffi::generate_scaffolding("src/zmanager_ffi.udl").expect("UDL scaffolding generation failed");
}
