use alloy::signers::local::PrivateKeySigner;
use dstack_sdk_types::dstack::GetKeyResponse;

pub fn to_account(
    get_key_response: &GetKeyResponse,
) -> Result<PrivateKeySigner, Box<dyn std::error::Error>> {
    let key_bytes = hex::decode(&get_key_response.key)?;
    let wallet = PrivateKeySigner::from_slice(&key_bytes)?;
    Ok(wallet)
}
