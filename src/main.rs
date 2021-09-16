mod colour_security;
mod tpm;

use std::convert::{TryFrom, TryInto};
use std::path::PathBuf;
use tss_esapi::abstraction::cipher::Cipher;
use tss_esapi::utils::create_restricted_decryption_rsa_public;
use tss_esapi::{
    constants::{tss::TPM2_PERSISTENT_FIRST, CapabilityType},
    handles::{ObjectHandle, PersistentTpmHandle, TpmHandle},
    interface_types::{
        dynamic_handles::Persistent,
        resource_handles::{Hierarchy, Provision},
        session_handles::AuthSession,
    },
    structures::{Auth, CapabilityData},
    tss2_esys::TPM2_HANDLE,
};
use tss_esapi::{tcti_ldr::TabrmdConfig, Context};

fn main() {
    // Test reading back stuff
    let mut context =
        Context::new_with_tabrmd(TabrmdConfig::default()).expect("Failed to open TPM!");
    // Set Password session

    // context.execute_with_sessions((Some(AuthSession::Password), None, None), |context| {
    //     let primary_key = crate::tpm::create_write_key(
    //         context,
    //         PathBuf::from("test_primary.key"),
    //         crate::tpm::KeyType::Primary,
    //         tpm::PersistType::Persist(u32::from_be_bytes([0x81, 0x05, 0x00, 0x01])),
    //         tpm::KeyAuthType::Password("test-password".to_string()),
    //     )
    //     .expect("Failed to create a primary key!");
    // });
    let read_primary_key =
        crate::tpm::load_key_from_file(&mut context, PathBuf::from("test_primary.key"))
            .expect("Failed to read back primary key!");
}
