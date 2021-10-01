#[macro_use]
extern crate lazy_static;

mod colour_security;
mod keygen;
mod tpm;

use tss_esapi::{tcti_ldr::TabrmdConfig, Context};

fn main() {
    // Test reading back stuff
    let mut context =
        Context::new_with_tabrmd(TabrmdConfig::default()).expect("Failed to open TPM!");
    // Set Password session
    keygen::check_create_keys(&mut context);
    keygen::create_colour_security_values(&mut context);

    // context.execute_with_sessions((Some(AuthSession::Password), None, None), |context| {
    //     crate::tpm::evict_key(context, ObjectHandle::None, 0x81050001)
    //         .expect("Failed to evict the created primary key!");

    //     let primary_key = crate::tpm::create_write_key(
    //         context,
    //         PathBuf::from("test_primary.key"),
    //         crate::tpm::KeyType::Primary,
    //         tpm::PersistType::Persist(u32::from_be_bytes([0x81, 0x05, 0x00, 0x01])),
    //         tpm::KeyAuthType::Password("test-password".to_string()),
    //     )
    //     .expect("Failed to create a primary key!");

    //     let read_primary_key =
    //         crate::tpm::load_key_from_file(context, PathBuf::from("test_primary.key"))
    //             .expect("Failed to read primary key.");

    //     context
    //         .tr_set_auth(
    //             read_primary_key.into(),
    //             &Auth::try_from("test-password".as_bytes())
    //                 .expect("failed to create authentication for parent key"),
    //         )
    //         .expect("Failed to authenticate parent key");

    //     let hmac_key = crate::tpm::create_write_key(
    //         context,
    //         PathBuf::from("test_hmac.key"),
    //         crate::tpm::KeyType::HMAC {
    //             parent_key: read_primary_key.into(),
    //         },
    //         tpm::PersistType::Persist(u32::from_be_bytes([0x81, 0x06, 0x00, 0x01])),
    //         tpm::KeyAuthType::Password("test-password".to_string()),
    //     )
    //     .expect("Failed to create a primary key!");
    // });
}
