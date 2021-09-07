use std::{convert::TryFrom, fs::File, path::PathBuf};
use tss_esapi::{
    abstraction::cipher::Cipher,
    attributes::ObjectAttributesBuilder,
    constants::tss::{TPM2_ALG_KEYEDHASH, TPM2_ALG_RSA, TPM2_ALG_SHA256},
    handles::KeyHandle,
    interface_types::resource_handles::Hierarchy,
    structures::{KeyedHashParameters, KeyedHashScheme, SymmetricDefinitionObject},
    utils::{PublicParmsUnion, Tpm2BPublicBuilder, TpmsContext, TpmsRsaParmsBuilder},
    Context,
};

// This is to help with the create_write_key function
pub enum KeyType {
    Primary,
    HMAC { parent_key: KeyHandle }, // This KeyHandle is for the PRIMARY/parent KEY.
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
) -> Result<KeyHandle, Box<dyn std::error::Error>> {
    // Inspired from https://docs.rs/tss-esapi/6.1.0/tss_esapi/struct.Context.html#method.hmac

    // I found some documentation on the specific key attributes at
    // https://dev.to/nandhithakamal/tpm-part-1-4emf (I'll comment the specifics
    // on each line)
    //
    // I believe key attributes have to do with portability and how the key
    // should be treated in the TPM. Not all of this is perfectly clear to me at the moment,
    // and the article I linked above doesn't cover everything.
    let mut key_attributes = ObjectAttributesBuilder::new()
        .with_sensitive_data_origin(true)
        // Tells us that the TPM made this key.
        // I don't really understand from what I linked above.
        // Keeping it though since I believe it's a default in tpm2_createprimary. (??)
        .with_user_with_auth(true);

    // Apparently this can ONLY be anbled for HMAC otherwise
    // primary key creation will fail.
    if let KeyType::HMAC { .. } = key_type {
        key_attributes = key_attributes.with_sign_encrypt(true)
    } else {
        // Apparently enabling some of these attributes makes the HMAC hashing broken
        key_attributes = key_attributes
            // This is probably pointless since we're not going to be signing any keys anyway,
            // but I'm keeping it since it's a default within tpm2_createprimary
            .with_restricted(true)
            .with_fixed_parent(true) // tpm2-tools's tpm2_createprimary does this, so why not
            .with_fixed_tpm(true) // According to the web page I found, this probably means that
            // Allows this key to be a parent key (for the HMAC key)
            .with_decrypt(true);
    }
    let key_attributes = key_attributes.build()?;

    // We use RSA for the primary key, since examples and such, although
    // ECC would probably work as well.
    let public_key = Tpm2BPublicBuilder::new()
        .with_type(if let KeyType::Primary = key_type {
            // We do an RSA key if this is a primary key
            TPM2_ALG_RSA
        } else {
            // We do a KEYEDHASH type of key for HMAC keys.
            //
            // See https://docs.rs/tss-esapi/6.1.0/tss_esapi/struct.Context.html#method.hmac
            // for original inspiration
            TPM2_ALG_KEYEDHASH
        })
        .with_name_alg(TPM2_ALG_SHA256)
        .with_parms(if let KeyType::Primary = key_type {
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
        } else {
            // This is what the example uses, but this is an HMAC with sha256
            PublicParmsUnion::KeyedHashDetail(KeyedHashParameters::new(
                KeyedHashScheme::HMAC_SHA_256,
            ))
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
            KeyType::HMAC { parent_key } => {
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

        // Test writing two keys
        let primary_key = crate::tpm::create_write_key(
            &mut ctx,
            PathBuf::from("test_primary.key"),
            crate::tpm::KeyType::Primary,
        )
        .expect("Failed to create a primary key!");

        let hmac_key = crate::tpm::create_write_key(
            &mut ctx,
            PathBuf::from("test_hmac.key"),
            crate::tpm::KeyType::HMAC {
                parent_key: primary_key,
            },
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
        let hmac_data = MaxBuffer::try_from("There is no spoon".as_bytes().to_vec())
            .expect("Failed to convert the data for HMAC-ing");

        let hmac_written = ctx
            .execute_with_nullauth_session(|ctx| {
                ctx.hmac(hmac_key.into(), &hmac_data, HashingAlgorithm::Sha256)
            })
            .expect("Failed to HMAC the written key");

        let hmac_read = ctx
            .execute_with_nullauth_session(|ctx| {
                ctx.hmac(read_hmac_key.into(), &hmac_data, HashingAlgorithm::Sha256)
            })
            .expect("Failed to HMAC the read key");

        // Check if the written and the read HMACs are the same
        assert_eq!(hmac_written, hmac_read);

        // Clean up
        std::fs::remove_file("test_primary.key")
            .expect("Failed to remove primary key from filesystem");
        std::fs::remove_file("test_hmac.key").expect("Failed to remove HMAC key from filesystem");
    }
}
