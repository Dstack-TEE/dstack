use crate::dstack_client::GetKeyResponse;
use alloy::signers::local::PrivateKeySigner;

pub fn to_account(
    get_key_response: &GetKeyResponse,
) -> Result<PrivateKeySigner, Box<dyn std::error::Error>> {
    let key_bytes = hex::decode(&get_key_response.key)?;
    let wallet = PrivateKeySigner::from_slice(&key_bytes)?;
    Ok(wallet)
}
