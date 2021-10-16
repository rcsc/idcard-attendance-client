use crate::colour_security::ColourSecurityValue;
use tss_esapi::handles::KeyHandle;

pub mod sign_in;
pub mod unlock_keys;

pub struct AttendanceData {
    pub barcode_value: String,
    pub colour_security_value: ColourSecurityValue,
    pub security_pin: String,
}

#[derive(Default, Debug)]
pub struct KeyData {
    pub aes_key_handle: Option<KeyHandle>,
    pub hmac_key_handle: Option<KeyHandle>,
}
