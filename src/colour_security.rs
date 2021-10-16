// Colour security allows people to choose a colour for security purposes. It makes it so that the client device is required, along with the TPM together,
// for generating a valid ID hash.

#[derive(Debug)]
pub enum ColourSecurityValue {
    Green,
    Red,
    Blue,
    Orange,
}
