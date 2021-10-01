// Generate the keys that we're going to need to use

use crate::tpm;
use directories::ProjectDirs;
use rand::distributions::Alphanumeric;
use std::path::PathBuf;

use rand::prelude::*;
use std::{convert::TryFrom, fs::create_dir_all};
use tss_esapi::{
    handles::KeyHandle, interface_types::session_handles::AuthSession, structures::Auth, Context,
};

lazy_static! {
    pub static ref APP_DATA: ProjectDirs = {
        let project_dirs = ProjectDirs::from("club", "ridgecompsci", "TPMAttendance")
            .expect("failed to make project dirs");

        project_dirs
    };
}

pub fn create_colour_security_values(context: &mut Context) {
    // Blue, orange, red, green are the colours we're going to use

    // This directory will store randomly-generated strings of length 32
    // that have been encrypted with the generated AES key from check_create_keys.
    //
    // If you haven't run check_create_keys(&mut ctx), you should do that before
    // running this function.
    let colour_security_dir = APP_DATA.data_dir().join("colour_security");
    create_dir_all(&colour_security_dir).expect("Failed to make colour security data dir");

    // Load AES key and authenticate it
    let aes_key_path = APP_DATA.data_dir().join("keys").join("aes.key");
    let aes_key_unlocked = get_unlocked_key(
        context,
        "Enter the password for the AES key: ".to_string(),
        aes_key_path,
    );

    // Create a random value generator and use that to make an iterator
    let randomizer = rand_chacha::ChaChaRng::from_entropy();
    let mut random_colour_security_gen = randomizer.sample_iter(&Alphanumeric);

    // Go through each colour and generate a random sequence that will be encrypted
    for colour in ["blue", "orange", "red", "green"] {
        // 32-length random string for colour security data
        let random_colour_security_key: String = (&mut random_colour_security_gen)
            .take(32)
            .map(char::from)
            .collect();

        // Encrypt the random value
        let aes_encryption_data = context
            .execute_with_nullauth_session(|ctx| {
                crate::tpm::aes_encrypt(
                    ctx,
                    aes_key_unlocked.into(),
                    random_colour_security_key.into(),
                )
            })
            .expect(&format!(
                "Failed to AES encrypt the {} colour security data",
                colour
            ));

        // Write the encrypted data (including the IV) to the filesystem
        std::fs::write(
            colour_security_dir.join(colour),
            bincode::serialize(&aes_encryption_data).expect(&format!(
                "Failed to serialize AES encryption data to write the {} colour security data!",
                colour
            )),
        )
        .expect("Failed to write blue colour security data?");

        println!(
            "Generated the {} colour security data and wrote it to the filesystem successfully.",
            colour
        );
    }
}

pub fn get_unlocked_key(
    context: &mut Context,
    prompt: String,
    file: PathBuf,
) -> tss_esapi::handles::KeyHandle {
    let primary_key_password =
        rpassword::prompt_password_stdout(&prompt).expect("Failed to read primary key password!");

    let read_primary_key =
        crate::tpm::load_key_from_file(context, file).expect("Failed to read primary key.");

    context
        .tr_set_auth(
            read_primary_key.into(),
            &Auth::try_from(primary_key_password.into_bytes())
                .expect("Failed to convert password to binary to authenticate primary key!"),
        )
        .expect("Failed to set the password for primary key when creating child keys!");

    read_primary_key
}

// Helper utility to check if keys are being created,
// and if they're not, make the keys and let the user input the password and make the keys.
pub fn check_create_keys(
    context: &mut Context,
) -> (Option<KeyHandle>, Option<KeyHandle>, Option<KeyHandle>) {
    let key_dir = APP_DATA.data_dir().join("keys");
    let (primary_key_file, aes_key_file, hmac_key_file) = (
        key_dir.join("primary.key"),
        key_dir.join("aes.key"),
        key_dir.join("hmac.key"),
    );

    // Make sure the directory exists before we set about doing anything
    create_dir_all(key_dir).expect("Failed to make key data dir");

    // This will only work if the key is already created
    let get_unlocked_primary_key = |context: &mut Context| -> tss_esapi::handles::KeyHandle {
        get_unlocked_key(
            context,
            "Enter primary key password: ".to_owned(),
            primary_key_file.clone(),
        )
    };

    // So we don't have to provide a parent key to create_key_helper()
    #[derive(Debug)]
    enum CreateKeyType {
        Primary,
        AES,
        HMAC,
    }

    let create_key_helper = |context: &mut Context, create_key_type: CreateKeyType| -> KeyHandle {
        let create_key_password = rpassword::prompt_password_stdout(&format!(
            "{} key does not exist. Please provide a password to create it: ",
            match &create_key_type {
                CreateKeyType::AES => "AES",
                CreateKeyType::HMAC => "HMAC",
                CreateKeyType::Primary => "Primary",
            }
        ))
        .expect("Failed to read password for key to create!");

        // For creating the key
        let key_type = match create_key_type {
            CreateKeyType::Primary => crate::tpm::KeyType::Primary,
            // TODO how do we keep this DRY?
            CreateKeyType::AES => crate::tpm::KeyType::AES {
                parent_key: get_unlocked_primary_key(context),
            },
            CreateKeyType::HMAC => crate::tpm::KeyType::HMAC {
                parent_key: get_unlocked_primary_key(context),
            },
        };

        generate_primary_aes_hmac_keys(context, key_type, create_key_password)
    };

    let primary_key_handle = if !primary_key_file.exists() {
        Some(create_key_helper(context, CreateKeyType::Primary))
    } else {
        None
    };

    let aes_key_handle = if !aes_key_file.exists() {
        Some(create_key_helper(context, CreateKeyType::AES))
    } else {
        None
    };

    let hmac_key_handle = if !hmac_key_file.exists() {
        Some(create_key_helper(context, CreateKeyType::HMAC))
    } else {
        None
    };

    (primary_key_handle, aes_key_handle, hmac_key_handle)
}

pub fn generate_primary_aes_hmac_keys(
    context: &mut Context,
    // Yes, the handle you give has to be unlocked before you put it here
    primary_key: crate::tpm::KeyType,
    password: String,
) -> KeyHandle {
    // TODO in future versions of this, we might want to randomize the addresses.
    let (address_byte, key_filename) = match primary_key {
        crate::tpm::KeyType::AES { .. } => (0x06, "aes.key"),
        crate::tpm::KeyType::Primary => (0x05, "primary.key"),
        crate::tpm::KeyType::HMAC { .. } => (0x07, "hmac.key"),
    };

    context
        .execute_with_sessions((Some(AuthSession::Password), None, None), |context| {
            let create_write_key_result = crate::tpm::create_write_key(
                context,
                APP_DATA.data_dir().join("keys").join(key_filename),
                primary_key,
                tpm::PersistType::Persist(u32::from_be_bytes([0x81, address_byte, 0x00, 0x01])),
                tpm::KeyAuthType::Password(password),
            );

            let _password_incorrect_error = Box::new(tss_esapi::Error::Tss2Error(
                tss_esapi::constants::response_code::Tss2ResponseCode::FormatOne(
                    tss_esapi::constants::response_code::FormatOneResponseCode { 0: 0x0000098e },
                ),
            ));

            if let Err(_password_incorrect_error) = create_write_key_result {
                println!("Incorrect parent key password! Could not create key.");
                std::process::exit(0);
            } else if let Ok(key) = create_write_key_result {
                key
            } else {
                panic!(
                    "Unhandled error occurred when creating the key {:?}",
                    create_write_key_result
                )
            }
        })
        .into()
}
