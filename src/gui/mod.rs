use tss_esapi::handles::KeyHandle;

pub mod sign_in;
pub mod unlock_keys;

#[derive(Default)]
pub struct AttendanceData {}

#[derive(Default, Debug)]
pub struct KeyData {
    pub aes_key_handle: Option<KeyHandle>,
    pub hmac_key_handle: Option<KeyHandle>,
}
