mod colour_security;
mod tpm;

use std::path::PathBuf;
use tss_esapi::{tcti_ldr::TabrmdConfig, Context};

fn main() {
    // Test reading back stuff
    let mut ctx = Context::new_with_tabrmd(TabrmdConfig::default()).expect("Failed to open TPM!");
    let primary_key = crate::tpm::create_write_key(
        &mut ctx,
        PathBuf::from("test_primary.key"),
        crate::tpm::KeyType::Primary,
        tpm::PersistType::Persist(u32::from_be_bytes([0x81, 0x00, 0x00, 0x20])),
    )
    .expect("Failed to create a primary key!");
    // let _read_primary_key =
    // crate::tpm::load_key_from_file(&mut ctx, PathBuf::from("test_primary.key"))
    // .expect("Failed to read back primary key!");
}
