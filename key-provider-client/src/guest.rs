use sodiumoxide::crypto::box_::{self, PublicKey, SecretKey};
use sodiumoxide::crypto::sealedbox;
use std::sync::OnceLock;

pub use box_::PUBLICKEYBYTES;

#[allow(clippy::result_unit_err)]
fn ensure_sodium_initialized() -> Result<(), ()> {
    static SODIUM_INIT: OnceLock<Result<(), ()>> = OnceLock::new();
    *SODIUM_INIT.get_or_init(sodiumoxide::init)
}

pub fn generate_keypair() -> (PublicKey, SecretKey) {
    ensure_sodium_initialized().expect("Failed to initialize sodium");
    box_::gen_keypair()
}

#[allow(clippy::result_unit_err)]
pub fn open_sealed_box(
    sealed_box: &[u8],
    public_key: &PublicKey,
    secret_key: &SecretKey,
) -> Result<Vec<u8>, ()> {
    ensure_sodium_initialized().expect("Failed to initialize sodium");
    sealedbox::open(sealed_box, public_key, secret_key)
}
