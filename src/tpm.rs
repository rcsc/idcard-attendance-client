use rand::prelude::*;
use rand_chacha::rand_core::SeedableRng;
use serde::{Deserialize, Serialize};
use std::{
    convert::{TryFrom, TryInto},
    fs::File,
    path::PathBuf,
};
use tss_esapi::{
    abstraction::cipher::Cipher,
    attributes::ObjectAttributesBuilder,
    constants::tss::{TPM2_ALG_KEYEDHASH, TPM2_ALG_RSA, TPM2_ALG_SHA256, TPM2_ALG_SYMCIPHER},
    handles::{KeyHandle, ObjectHandle, PersistentTpmHandle},
    interface_types::{
        algorithm::SymmetricMode,
        dynamic_handles::Persistent,
        resource_handles::{Hierarchy, Provision},
    },
    structures::{
        InitialValue, KeyedHashParameters, KeyedHashScheme, MaxBuffer, SymmetricDefinitionObject,
    },
    utils::{PublicParmsUnion, Tpm2BPublicBuilder, TpmsContext, TpmsRsaParmsBuilder},
    Context,
};

#[derive(Serialize, Deserialize)]
pub struct AESEncryptionData {
    initialisation_vector: [u8; 16],
    encrypted_bytes: Vec<u8>,
}

// Generates an IV, takes a u8 vec and encrypts it with
// the provided key.
pub fn aes_encrypt(
    ctx: &mut Context,
    aes_key: KeyHandle,
    data: Vec<u8>,
) -> Result<AESEncryptionData, Box<dyn std::error::Error>> {
    let data_maxbuffer = MaxBuffer::try_from(data)?;

    // Randomly generate an IV --- 128 bit (16 byte) array
    // We use an CSPRNG to make the IV more secure (or something like that).
    let mut randomizer = rand_chacha::ChaChaRng::from_entropy();
    let iv: [u8; 16] = randomizer.gen();

    // Keep this so we can return it later.
    let iv = InitialValue::try_from(Vec::from(iv)).unwrap();

    Ok(AESEncryptionData {
        encrypted_bytes: ctx
            .encrypt_decrypt_2(
                aes_key,
                false, // this parameter is true when we want to decrypt and false when we want to encrypt
                // https://stackoverflow.com/questions/1220751/how-to-choose-an-aes-encryption-mode-cbc-ecb-ctr-ocb-cfb
                // for a decision to use CTR
                //
                // NOTE: If you create the AES key with a different mode than what you use here
                // (eg. make an aes-cfb key and use CTR mode here),
                // you will likely get an "Esys Finish ErrorCode 0x000003c9."
                SymmetricMode::Ctr,
                &data_maxbuffer,
                &iv,
            )?
            .0
            .value()
            .to_vec(),
        // The output IV that encrypt_decrypt_2 is completely wrong.
        // So we return the original randomly-generated IV.
        initialisation_vector: <[u8; 16]>::try_from(iv.value())?,
    })
}

// Given an IV, takes a u8 vec of encrypted data
// and decrypts it with the provided initialisation vector
// and provided key.
pub fn aes_decrypt(
    ctx: &mut Context,
    aes_key: KeyHandle,
    encryption_data: &AESEncryptionData,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // We don't want the caller to lose ownership of AESEncryption,
    // so we use a referenc ehere.
    let data_maxbuffer = MaxBuffer::try_from(encryption_data.encrypted_bytes.clone())?;

    Ok(ctx
        .encrypt_decrypt_2(
            aes_key,
            true, // true if decrypting, false if encrypting
            SymmetricMode::Ctr,
            &data_maxbuffer,
            &InitialValue::try_from(encryption_data.initialisation_vector.to_vec())?,
        )?
        .0
        .value()
        .to_vec())
}

// This is to help with the create_write_key function
pub enum KeyType {
    Primary,
    HMAC { parent_key: KeyHandle }, // This KeyHandle is for the PRIMARY/parent KEY.
    AES { parent_key: KeyHandle },
}

pub enum PersistType {
    Persist(u32), // 4 byte array for a u32 memory address, or something like that.
    Temporary,
}

// Load a key from a context file written by create_write_key to a KeyHandle struct
pub fn load_key_from_file(
    ctx: &mut Context,
    path: PathBuf,
) -> Result<KeyHandle, Box<dyn std::error::Error>> {
    let key_context: TpmsContext = bincode::deserialize_from(File::open(path)?)?;

    // We would use map and just return right here, but it seems like the map
    // function on Result doesn't cause the error to be wrapped into a box.
    //
    // Mapping the error would just use more lines of code...
    let loaded_key = ctx.context_load(key_context)?;
    Ok(loaded_key.into())
}

// Create a key and store it on the TPM (primary key or HMAC key, doesn't matter).
//
// This function will save the key's context(?) to the specified file.
// Ideally, we don't even need to create a primary key, but like, according to Stack Overflow,
// if we want to be incredibly paranoid, we can do it.
//
// This function returns the KeyHandle that is saved to the context file at the end, if everything
// is successful..
pub fn create_write_key(
    ctx: &mut Context,
    output_context: PathBuf,
    key_type: KeyType,
    // Should we persist the key between reboots? Also, this is an enum for readability when invoking this function.
    persist: PersistType,
    // We use an ObjectHandle since if you persist, the KeyHandle ends up getting turned into an ObjectHandle
) -> Result<ObjectHandle, Box<dyn std::error::Error>> {
    // Inspired from https://docs.rs/tss-esapi/6.1.0/tss_esapi/struct.Context.html#method.hmac

    // I found some documentation on the specific key attributes at
    // https://dev.to/nandhithakamal/tpm-part-1-4emf (I'll comment the specifics
    // on each line). It looks like this documentaiton might be totally wrong though
    //
    // I believe key attributes have to do with portability and how the key
    // should be treated in the TPM. Not all of this is perfectly clear to me at the moment,
    // and the article I linked above doesn't cover everything.
    let mut key_attributes = ObjectAttributesBuilder::new()
        // Tells us that the TPM made this key.
        // I don't really understand from what I linked above.
        // Keeping it though since I believe it's a default in tpm2_createprimary. (??)
        .with_user_with_auth(true);

    // Apparently this can ONLY be anbled for HMAC otherwise
    // primary key creation will fail.
    match key_type {
        KeyType::HMAC { .. } => {
            key_attributes = key_attributes
                .with_sensitive_data_origin(true)
                .with_sign_encrypt(true)
        }
        KeyType::AES { .. } => {
            key_attributes = key_attributes
                .with_sensitive_data_origin(true)
                .with_sign_encrypt(true)
                .with_decrypt(true);
        }
        KeyType::Primary => {
            // Apparently enabling some of these attributes makes the HMAC hashing broken
            key_attributes = key_attributes
                // This is probably pointless since we're not going to be signing any keys anyway,
                // but I'm keeping it since it's a default within tpm2_createprimary
                .with_sensitive_data_origin(true)
                .with_restricted(true)
                .with_fixed_parent(true) // tpm2-tools's tpm2_createprimary does this, so why not
                .with_fixed_tpm(true) // According to the web page I found, this probably means that
                // Allows this key to be a parent key (for the HMAC key)
                .with_decrypt(true)
                .with_sign_encrypt(false);
        }
    }
    let key_attributes = key_attributes.build()?;

    // We use RSA for the primary key, since examples and such, although
    // ECC would probably work as well.
    let public_key = Tpm2BPublicBuilder::new()
        .with_type(match key_type {
            KeyType::Primary => {
                // We do an RSA key if this is a primary key
                TPM2_ALG_RSA
            }
            KeyType::HMAC { .. } => {
                // We do a KEYEDHASH type of key for HMAC keys.
                //
                // See https://docs.rs/tss-esapi/6.1.0/tss_esapi/struct.Context.html#method.hmac
                // for original inspiration
                TPM2_ALG_KEYEDHASH
            }
            KeyType::AES { .. } => TPM2_ALG_SYMCIPHER,
        })
        .with_name_alg(TPM2_ALG_SHA256)
        .with_parms(match key_type {
            KeyType::Primary => {
                PublicParmsUnion::RsaDetail(
                    // TpmsRsaParmsBuilder seems to be undocumented, so I had to use
                    // https://github.com/parallaxsecond/rust-tss-esapi/blob/main/tss-esapi/src/utils/mod.rs
                    //
                    // We could actually just use tss_esapi::utils::create_restricted_decryption_rsa_public, butS
                    // whatever. I don't get to set key attributes with that.
                    TpmsRsaParmsBuilder::new_restricted_decryption_key(
                        // Again, this is what tpm2_createprimary does.
                        SymmetricDefinitionObject::try_from(Cipher::aes_128_cfb())?.into(),
                        2048, // We attempt to replicate tpm2_createprimary whenever we can
                        0,    // Setting this to zero generates the "default" RSA exponent 2^16 + 1.
                    )
                    .build()?,
                )
            }
            KeyType::HMAC { .. } => {
                // This is what the example uses, but this is an HMAC with sha256
                PublicParmsUnion::KeyedHashDetail(KeyedHashParameters::new(
                    KeyedHashScheme::HMAC_SHA_256,
                ))
            }
            // I got this information from the test/example here:
            // https://github.com/parallaxsecond/rust-tss-esapi/blob/main/tss-esapi/tests/context_tests/tpm_commands/symmetric_primitives_tests.rs#L66
            KeyType::AES { .. } => {
                // Create aes128ctr key, so we can do the CTR variant of AES encryption
                PublicParmsUnion::SymDetail(Cipher::aes(SymmetricMode::Ctr, 128)?)
            }
        })
        .with_object_attributes(key_attributes)
        .build()?;

    ctx.execute_with_nullauth_session(|ctx| {
        let key_handle = match key_type {
            KeyType::Primary => {
                // Endorsement hierarchy is for verification and attestation or something,
                // which is kinda what we're doing here, so we might as well use the
                // endorsement hierarchy.
                ctx.create_primary(Hierarchy::Owner, &public_key, None, None, None, None)?
                    .key_handle
            }
            KeyType::HMAC { parent_key } | KeyType::AES { parent_key } => {
                println!("Parent key is {:#?}", parent_key);
                // Create the HMAC key based off of the parent key.

                let created_hmac_key = ctx
                    .create(parent_key, &public_key, None, None, None, None)
                    .expect("fail");

                // To get a KeyHandle for the new key, you need to plug in the newly-
                // created key into the parent key handle.
                ctx.load(
                    parent_key,
                    created_hmac_key.out_private,
                    created_hmac_key.out_public,
                )?
            }
        };

        let key_handle = if let PersistType::Persist(address) = persist {
            // Documentation found at https://github.com/parallaxsecond/rust-tss-esapi/blob/main/tss-esapi/tests/context_tests/tpm_commands/context_management_tests.rs#L225
            // We are panicking since this stuff is not working yet.
            let persist_tpm_handle = PersistentTpmHandle::new(address)
                .expect("Failed to create persistent TPM handle parameters.");
            let persist = Persistent::Persistent(persist_tpm_handle);

            // TODO what if some key already exists at the given address?
            // The example handles this but we do not. I suspect we should error
            // instead of removing the handle, like the example does.
            //
            // It's worth mentioning that the owner provision is what
            // tpm2_evictcontrol uses by default
            ctx.evict_control(Provision::Owner, key_handle.into(), persist)
                .expect("Failed to persist TPM key!")
        } else {
            key_handle.into()
        };

        let key_serializable = ctx.context_save(key_handle.into())?;

        // To annoy people more (even though
        // it really won't matter), why not just serialize the context to a binary format?
        let write_key = File::create(output_context)?;
        bincode::serialize_into(write_key, &key_serializable)?;

        Ok(key_handle)
    })
}

#[cfg(test)]
mod tpm_tests {
    use std::convert::TryFrom;
    use std::path::PathBuf;
    use tss_esapi::{
        interface_types::algorithm::HashingAlgorithm, structures::MaxBuffer,
        tcti_ldr::TabrmdConfig, Context,
    };

    #[test]
    pub fn create_write_read_keys() {
        // Create a context
        let mut ctx =
            Context::new_with_tabrmd(TabrmdConfig::default()).expect("Failed to open TPM!");

        // Test writing three keys
        let primary_key = crate::tpm::create_write_key(
            &mut ctx,
            PathBuf::from("test_primary.key"),
            crate::tpm::KeyType::Primary,
            crate::tpm::PersistType::Temporary,
        )
        .expect("Failed to create a primary key!");

        let hmac_key = crate::tpm::create_write_key(
            &mut ctx,
            PathBuf::from("test_hmac.key"),
            crate::tpm::KeyType::HMAC {
                parent_key: primary_key.into(),
            },
            crate::tpm::PersistType::Persist(0x81020001),
        )
        .expect("Failed to create an hmac key!");
        let aes_key = crate::tpm::create_write_key(
            &mut ctx,
            PathBuf::from("test_aes.key"),
            crate::tpm::KeyType::AES {
                parent_key: primary_key.into(),
            },
            crate::tpm::PersistType::Persist(0x81000020),
        )
        .expect("Failed to create an hmac key!");

        // Test reading two keys

        // TODO actually test using the primary key to encrypt and decrypt data
        let _read_primary_key =
            crate::tpm::load_key_from_file(&mut ctx, PathBuf::from("test_primary.key"))
                .expect("Failed to read back primary key!");
        let read_hmac_key =
            crate::tpm::load_key_from_file(&mut ctx, PathBuf::from("test_hmac.key"))
                .expect("Failed to read back hmac key!");

        // Try running an hmac on the two keys. If they have the same output,
        // then the two keys are the same.
        let test_data = MaxBuffer::try_from("test data to hmac".as_bytes().to_vec())
            .expect("Failed to convert the data for HMAC-ing");

        let hmac_written = ctx
            .execute_with_nullauth_session(|ctx| {
                ctx.hmac(hmac_key.into(), &test_data, HashingAlgorithm::Sha256)
            })
            .expect("Failed to HMAC the written key");

        let hmac_read = ctx
            .execute_with_nullauth_session(|ctx| {
                ctx.hmac(read_hmac_key.into(), &test_data, HashingAlgorithm::Sha256)
            })
            .expect("Failed to HMAC the read key");

        let aes_encryption_data = ctx
            .execute_with_nullauth_session(|ctx| {
                crate::tpm::aes_encrypt(ctx, aes_key.into(), vec![1, 2, 3, 4, 5, 6, 7])
            })
            .expect("failed to AES encrypt a sequence");

        let decrypted_data = ctx
            .execute_with_nullauth_session(|ctx| {
                crate::tpm::aes_decrypt(ctx, aes_key.into(), &aes_encryption_data)
            })
            .expect("failed to AES decrypt a sequence");

        assert_eq!(decrypted_data, vec![1, 2, 3, 4, 5, 6, 7]);

        // Check if the written and the read HMACs are the same
        assert_eq!(hmac_written, hmac_read);

        // Clean up
        std::fs::remove_file("test_primary.key")
            .expect("Failed to remove primary key from filesystem");
        std::fs::remove_file("test_hmac.key").expect("Failed to remove HMAC key from filesystem");
        std::fs::remove_file("test_aes.key").expect("Failed to remove AES key from filesystem");
    }
}
